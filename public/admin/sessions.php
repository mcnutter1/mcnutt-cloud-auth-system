<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/csrf.php';
require_once __DIR__.'/../../src/guard.php';
require_once __DIR__.'/../../src/logger.php';
require_admin();

$pdo = db();
$msg=null; $err=null;

// Revoke (kill) a session or all sessions for a principal
if($_SERVER['REQUEST_METHOD']==='POST' && in_array(($_POST['action'] ?? ''), ['kill','kill_all'], true)){
  csrf_validate();
  try{
    if(($_POST['action'] ?? '') === 'kill'){
      $sid = (int)($_POST['id'] ?? 0);
      if($sid<=0) throw new Exception('Invalid session id.');
      // Fetch before update for logging
      $st = $pdo->prepare('SELECT * FROM sessions WHERE id=? LIMIT 1');
      $st->execute([$sid]);
      $sess = $st->fetch(PDO::FETCH_ASSOC);
      if(!$sess) throw new Exception('Session not found.');
      if($sess['revoked_at'] !== null){ $msg='Session already revoked.'; }
      else {
        $pdo->prepare('UPDATE sessions SET revoked_at=NOW() WHERE id=?')->execute([$sid]);
        $msg='Session revoked.';
        $actorId = (int)($_SESSION['pid'] ?? 0);
        log_event($pdo, 'user', $actorId, 'admin.session.revoke', [
          'session_id'=>$sid,
          'user_type'=>$sess['user_type'],
          'user_id'=>(int)$sess['user_id'],
          'reason'=>'admin_kill'
        ]);
      }
    } else { // kill_all
      $uType = $_POST['user_type'] ?? '';
      $uId   = (int)($_POST['user_id'] ?? 0);
      if(!in_array($uType, ['user','magic'], true) || $uId<=0) throw new Exception('Invalid principal.');
      $pdo->prepare("UPDATE sessions SET revoked_at=NOW() WHERE user_type=? AND user_id=? AND revoked_at IS NULL")->execute([$uType,$uId]);
      $msg='All sessions revoked for principal.';
      $actorId = (int)($_SESSION['pid'] ?? 0);
      log_event($pdo, 'user', $actorId, 'admin.session.revoke_all', [
        'user_type'=>$uType,
        'user_id'=>$uId,
        'reason'=>'admin_kill_all'
      ]);
    }
  }catch(Throwable $e){ $err=$e->getMessage(); }
}

// Filters
$actorType = trim($_GET['actor_type'] ?? '');
$q         = trim($_GET['q'] ?? ''); // username/email/app/ip contains
$includeRevoked = isset($_GET['include_revoked']) ? (int)$_GET['include_revoked'] : 0;
$limit     = (int)($_GET['limit'] ?? 50); if($limit<1) $limit=50; if($limit>200) $limit=200;
$page      = max(1, (int)($_GET['page'] ?? 1));
$offset    = ($page-1)*$limit;

$w = [];$p=[];
if($includeRevoked!==1){ $w[] = 's.revoked_at IS NULL AND s.expires_at>NOW()'; }
if($actorType!==''){ $w[]='s.user_type = ?'; $p[]=$actorType; }
if($q!==''){
  $w[] = '(u.username LIKE ? OR m.email LIKE ? OR s.app_id LIKE ? OR s.ip LIKE ?)';
  $p[] = '%'.$q.'%'; $p[]='%'.$q.'%'; $p[]='%'.$q.'%'; $p[]='%'.$q.'%';
}
$where = $w ? ('WHERE '.implode(' AND ',$w)) : '';

// Count
$countSt = $pdo->prepare("SELECT COUNT(*) FROM sessions s LEFT JOIN users u ON (s.user_type='user' AND s.user_id=u.id) LEFT JOIN magic_keys m ON (s.user_type='magic' AND s.user_id=m.id) $where");
$countSt->execute($p); $total = (int)$countSt->fetchColumn();

$limitSql=(int)$limit; $offsetSql=(int)$offset;
$sql = "SELECT s.*, u.username, m.email FROM sessions s LEFT JOIN users u ON (s.user_type='user' AND s.user_id=u.id) LEFT JOIN magic_keys m ON (s.user_type='magic' AND s.user_id=m.id) $where ORDER BY (s.last_seen_at IS NULL) ASC, s.last_seen_at DESC, s.issued_at DESC LIMIT $limitSql OFFSET $offsetSql";
$st = $pdo->prepare($sql); $st->execute($p);
$rows = $st->fetchAll(PDO::FETCH_ASSOC);

// Precompute activity counts per session (access.authorized + token.validate.success within lifecycle and same IP)
function session_window_bounds(array $r): array {
  $from = $r['issued_at'];
  $to   = $r['revoked_at'] ?? (new DateTimeImmutable())->format('Y-m-d H:i:s');
  if($r['expires_at'] && $r['expires_at'] < $to){ $to = $r['expires_at']; }
  return [$from, $to];
}

require_once __DIR__.'/_partials/header.php';
?>
<div class="container py-4">
  <h1 class="h4 mb-3">Sessions</h1>
  <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
  <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>

  <form method="get" class="card shadow-sm mb-3"><div class="card-body">
    <div class="row g-3 align-items-end">
      <div class="col-12 col-md-3">
        <label class="form-label">Actor Type</label>
        <select class="form-select" name="actor_type">
          <option value="">All</option>
          <?php foreach(['user','magic'] as $t): ?>
            <option value="<?=$t?>" <?php if($actorType===$t) echo 'selected'; ?>><?=$t?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-12 col-md-4">
        <label class="form-label">Search</label>
        <input class="form-control" name="q" placeholder="username, email, app, IP" value="<?=htmlspecialchars($q)?>" />
      </div>
      <div class="col-6 col-md-2">
        <label class="form-label">Per Page</label>
        <select class="form-select" name="limit">
          <?php foreach([25,50,100,200] as $n): ?>
            <option value="<?=$n?>" <?php if($limit===$n) echo 'selected'; ?>><?=$n?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-6 col-md-2">
        <div class="form-check mt-4 pt-2">
          <input class="form-check-input" type="checkbox" name="include_revoked" id="f-include-revoked" value="1" <?php if($includeRevoked===1) echo 'checked'; ?> />
          <label class="form-check-label" for="f-include-revoked">Include revoked/expired</label>
        </div>
      </div>
      <div class="col-12 col-md-1 d-grid">
        <button class="btn btn-primary">Filter</button>
      </div>
    </div>
  </div></form>

  <div class="card shadow-sm">
    <div class="card-body">
      <div class="table-responsive">
        <table class="table align-middle mb-0">
          <thead>
            <tr>
              <th>ID</th>
              <th>Actor</th>
              <th>Identity</th>
              <th>IP</th>
              <th>Last Seen</th>
              <th>Expires</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
          <?php foreach($rows as $r): $id=(int)$r['id']; $ident = $r['user_type']==='user' ? ($r['username'] ?? ('#'.$r['user_id'])) : ($r['email'] ?? ('#'.$r['user_id'])); list($from,$to) = session_window_bounds($r); ?>
            <tr class="cursor-pointer" onclick="toggleDetails(this)" title="Click to view details">
              <td class="text-muted small"><?=$id?></td>
              <td><span class="badge text-bg-secondary"><?=htmlspecialchars($r['user_type'])?></span></td>
              <td class="font-monospace small text-truncate" style="max-width:220px;" title="<?=htmlspecialchars($ident)?>"><?=htmlspecialchars($ident)?></td>
              <td class="small text-muted"><?=htmlspecialchars($r['ip'] ?? '')?></td>
              <td class="small"><?php echo $r['last_seen_at'] ? htmlspecialchars($r['last_seen_at']) : '<span class="text-muted">never</span>'; ?></td>
              <td class="small <?php echo (strtotime($r['expires_at'])<time())?'text-danger':''; ?>"><?=htmlspecialchars($r['expires_at'])?></td>
              <td class="text-end">
                <form method="post" onsubmit="return confirm('Revoke this session?');" class="d-inline">
                  <?php csrf_field(); ?>
                  <input type="hidden" name="action" value="kill" />
                  <input type="hidden" name="id" value="<?=$id?>" />
                  <button class="btn btn-sm btn-outline-danger" type="submit">Kill</button>
                </form>
              </td>
            </tr>
            <tr class="d-none"><td colspan="7">
              <div class="p-3 bg-light border rounded">
                <div class="row g-3">
                  <div class="col-md-4">
                    <div><strong>Lifecycle</strong></div>
                    <div class="small text-muted">Issued</div>
                    <div class="small font-monospace"><?=htmlspecialchars($r['issued_at'])?></div>
                    <div class="small text-muted mt-2">Last Seen</div>
                    <div class="small font-monospace"><?php echo $r['last_seen_at'] ? htmlspecialchars($r['last_seen_at']) : '<span class="text-muted">never</span>'; ?></div>
                    <div class="small text-muted mt-2">Expires</div>
                    <div class="small font-monospace"><?=htmlspecialchars($r['expires_at'])?></div>
                    <?php if($r['revoked_at']): ?>
                      <div class="small text-muted mt-2">Revoked</div>
                      <div class="small font-monospace text-danger"><?=htmlspecialchars($r['revoked_at'])?></div>
                    <?php endif; ?>
                  </div>
                  <div class="col-md-4">
                    <div><strong>Client</strong></div>
                    <div class="small text-muted">IP</div>
                    <div class="small font-monospace"><?=htmlspecialchars($r['ip'] ?? '')?></div>
                    <div class="small text-muted mt-2">User Agent</div>
                    <div class="small text-break"><?=htmlspecialchars($r['user_agent'] ?? '')?></div>
                    <div class="small text-muted mt-2">App ID</div>
                    <div class="small font-monospace"><?=htmlspecialchars($r['app_id'] ?? '')?></div>
                    <div class="small text-muted mt-2">Token</div>
                    <div class="small font-monospace"><?php $tok=$r['session_token']; echo htmlspecialchars(substr($tok,0,8).'…'.substr($tok,-4)); ?></div>
                  </div>
                  <div class="col-md-4">
                    <div><strong>Activity</strong></div>
                    <?php
                      // Count related activity during session window (same actor, same IP)
                      $aid = (int)$r['user_id']; $atype = $r['user_type']; $ip = $r['ip'] ?? null;
                      $cntAuth=0; $cntTok=0; $recent=[];
                      try{
                        $qs = 'SELECT COUNT(*) FROM logs WHERE actor_type=? AND actor_id=? AND event=? AND ts>=? AND ts<=?';
                        $params = [$atype,$aid,'access.authorized',$from,$to];
                        if($ip){ $qs .= ' AND ip<=>?'; $params[]=$ip; }
                        $st1=$pdo->prepare($qs); $st1->execute($params); $cntAuth=(int)$st1->fetchColumn();

                        $qs2 = 'SELECT COUNT(*) FROM logs WHERE actor_type=? AND actor_id=? AND event=? AND ts>=? AND ts<=?';
                        $params2 = [$atype,$aid,'token.validate.success',$from,$to];
                        if($ip){ $qs2 .= ' AND ip<=>?'; $params2[]=$ip; }
                        $st2=$pdo->prepare($qs2); $st2->execute($params2); $cntTok=(int)$st2->fetchColumn();

                        $qs3 = 'SELECT ts, event, ip FROM logs WHERE actor_type=? AND actor_id=? AND ts>=? AND ts<=?';
                        $params3 = [$atype,$aid,$from,$to];
                        if($ip){ $qs3 .= ' AND ip<=>?'; $params3[]=$ip; }
                        $qs3 .= ' ORDER BY ts DESC, id DESC LIMIT 10';
                        $st3=$pdo->prepare($qs3); $st3->execute($params3); $recent=$st3->fetchAll(PDO::FETCH_ASSOC);
                      }catch(Throwable $e){ /* ignore */ }
                    ?>
                    <div class="small">Access Authorized: <span class="fw-semibold"><?=$cntAuth?></span></div>
                    <div class="small">Token Validations: <span class="fw-semibold"><?=$cntTok?></span></div>
                    <div class="small mt-2 text-muted">Recent (this session)</div>
                    <?php if($recent): ?>
                      <ul class="small mb-2 ps-3">
                        <?php foreach($recent as $ev): ?>
                          <li><span class="text-muted"><?=htmlspecialchars(substr($ev['ts'],0,19))?></span> — <span class="font-monospace"><?=htmlspecialchars($ev['event'])?></span></li>
                        <?php endforeach; ?>
                      </ul>
                    <?php else: ?>
                      <div class="small text-muted">No recent events</div>
                    <?php endif; ?>
                    <a class="small me-2" href="/admin/logs.php?actor_type=<?=urlencode($r['user_type'])?>&from=<?=urlencode(str_replace(' ','T',substr($from,0,16)))?>&to=<?=urlencode(str_replace(' ','T',substr($to,0,16)))?><?php if($r['ip']) echo '&ip='.urlencode($r['ip']); ?>" target="_blank">View in Logs</a>
                    <form method="post" onsubmit="return confirm('Revoke ALL sessions for this user?');" class="d-inline">
                      <?php csrf_field(); ?>
                      <input type="hidden" name="action" value="kill_all" />
                      <input type="hidden" name="user_type" value="<?=htmlspecialchars($r['user_type'])?>" />
                      <input type="hidden" name="user_id" value="<?= (int)$r['user_id'] ?>" />
                      <button class="btn btn-sm btn-outline-danger">Kill All</button>
                    </form>
                  </div>
                </div>
              </div>
            </td></tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php $pages = max(1, (int)ceil($total/$limit)); if($pages>1): ?>
      <div class="d-flex justify-content-between align-items-center mt-3">
        <div class="small text-muted">Total: <?=$total?></div>
        <div class="btn-group">
          <?php for($i=1;$i<=$pages;$i++): $qs=$_GET; $qs['page']=$i; ?>
            <a class="btn btn-sm <?php echo ($i===$page)?'btn-primary':'btn-outline-secondary'; ?>" href="?<?=http_build_query($qs)?>"><?=$i?></a>
          <?php endfor; ?>
        </div>
      </div>
      <?php endif; ?>
    </div>
    <script>
      function toggleDetails(row){
        var next = row.nextElementSibling;
        if(!next) return;
        next.classList.toggle('d-none');
      }
    </script>
  </div>
  <div class="form-text mt-2">Showing <?=($includeRevoked===1?'all sessions (including revoked/expired)':'active sessions only')?>.</div>
  <div class="form-text">Click a row to view lifecycle, client, and activity details.</div>
</div>
<?php require __DIR__.'/_partials/footer.php'; ?>

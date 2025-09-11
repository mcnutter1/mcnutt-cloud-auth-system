<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/guard.php';
require_once __DIR__.'/../../src/secret_log.php';
require_admin();

$pdo = db();

// Read filters
$event      = trim($_GET['event'] ?? '');
$actorType  = trim($_GET['actor_type'] ?? '');
$from       = trim($_GET['from'] ?? ''); // datetime-local
$to         = trim($_GET['to'] ?? '');   // datetime-local
$ipLike     = trim($_GET['ip'] ?? '');
$q          = trim($_GET['q'] ?? '');    // detail contains
$limit      = (int)($_GET['limit'] ?? 50); if($limit<1) $limit=50; if($limit>500) $limit=500;
$page       = max(1, (int)($_GET['page'] ?? 1));
$offset     = ($page-1)*$limit;
$fmt        = trim($_GET['fmt'] ?? '');

$w=[]; $p=[];
if($event!==''){ $w[]='event = ?'; $p[]=$event; }
if($actorType!==''){ $w[]='actor_type = ?'; $p[]=$actorType; }
if($from!==''){ $w[]='ts >= ?'; $p[] = str_replace('T',' ',$from); }
if($to!==''){ $w[]='ts <= ?'; $p[] = str_replace('T',' ',$to); }
if($ipLike!==''){ $w[]='ip LIKE ?'; $p[] = '%'.$ipLike.'%'; }
if($q!==''){ $w[]='detail LIKE ?'; $p[] = '%'.$q.'%'; }
$where = $w ? ('WHERE '.implode(' AND ',$w)) : '';

// CSV export
if($fmt==='csv'){
  header('Content-Type: text/csv');
  header('Content-Disposition: attachment; filename="logs.csv"');
  $limitSql = (int)$limit; $offsetSql=(int)$offset;
  $sql = "SELECT id, ts, actor_type, actor_id, event, ip, detail FROM logs $where ORDER BY ts DESC, id DESC LIMIT $limitSql OFFSET $offsetSql";
  $st = $pdo->prepare($sql);
  $st->execute($p);
  $out = fopen('php://output','w');
  fputcsv($out, ['id','ts','actor_type','actor_id','event','ip','detail']);
  while($r=$st->fetch(PDO::FETCH_ASSOC)){
    fputcsv($out, [$r['id'],$r['ts'],$r['actor_type'],$r['actor_id'],$r['event'],$r['ip'], $r['detail']]);
  }
  fclose($out); exit;
}

// Count
$countSt = $pdo->prepare("SELECT COUNT(*) FROM logs $where");
$countSt->execute($p); $total = (int)$countSt->fetchColumn();

// Page query
$limitSql = (int)$limit; $offsetSql=(int)$offset;
$sql = "SELECT id, ts, actor_type, actor_id, event, ip, detail FROM logs $where ORDER BY ts DESC, id DESC LIMIT $limitSql OFFSET $offsetSql";
$st = $pdo->prepare($sql); $st->execute($p);
$rows = $st->fetchAll(PDO::FETCH_ASSOC);

// Distinct events for filter select
$eventOpts = $pdo->query("SELECT DISTINCT event FROM logs ORDER BY event")->fetchAll(PDO::FETCH_COLUMN);

require_once __DIR__.'/_partials/header.php';
?>
<div class="container py-4">
  <h1 class="h4 mb-3">Logs</h1>
  <form method="get" class="card shadow-sm mb-3"><div class="card-body">
    <div class="row g-3 align-items-end">
      <div class="col-12 col-md-3">
        <label class="form-label">Event</label>
        <select name="event" class="form-select">
          <option value="">All</option>
          <?php foreach($eventOpts as $opt): ?>
            <option value="<?=htmlspecialchars($opt)?>" <?php if($event===$opt) echo 'selected'; ?>><?=htmlspecialchars($opt)?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-6 col-md-2">
        <label class="form-label">Actor Type</label>
        <select name="actor_type" class="form-select">
          <option value="">All</option>
          <?php foreach(['user','magic','system'] as $t): ?>
            <option value="<?=$t?>" <?php if($actorType===$t) echo 'selected'; ?>><?=$t?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-6 col-md-3">
        <label class="form-label">From</label>
        <input type="datetime-local" class="form-control" name="from" value="<?=htmlspecialchars($from)?>">
      </div>
      <div class="col-6 col-md-3">
        <label class="form-label">To</label>
        <input type="datetime-local" class="form-control" name="to" value="<?=htmlspecialchars($to)?>">
      </div>
      <div class="col-6 col-md-2">
        <label class="form-label">IP</label>
        <input class="form-control" name="ip" value="<?=htmlspecialchars($ipLike)?>" placeholder="contains">
      </div>
      <div class="col-12 col-md-4">
        <label class="form-label">Search Detail</label>
        <input class="form-control" name="q" value="<?=htmlspecialchars($q)?>" placeholder="username, app_id, etc">
      </div>
      <div class="col-6 col-md-2">
        <label class="form-label">Per Page</label>
        <input class="form-control" type="number" name="limit" value="<?=htmlspecialchars((string)$limit)?>" min="1" max="500">
      </div>
      <div class="col-12 col-md-3 d-flex gap-2">
        <button class="btn btn-primary">Apply</button>
        <a class="btn btn-outline-secondary" href="logs.php">Reset</a>
        <button class="btn btn-outline-success" name="fmt" value="csv">Download CSV</button>
      </div>
    </div>
  </div></form>

  <div class="card shadow-sm">
    <div class="card-body">
      <div class="d-flex justify-content-between align-items-center mb-2">
        <div class="text-muted small">Total: <?=$total?> · Page <?=number_format($page)?> of <?=max(1, ceil($total/$limit))?></div>
        <div class="d-flex gap-2">
          <?php if($page>1): $qp=$_GET; $qp['page']=$page-1; ?><a class="btn btn-sm btn-outline-secondary" href="?<?=http_build_query($qp)?>">Prev</a><?php endif; ?>
          <?php if($offset+$limit<$total): $qn=$_GET; $qn['page']=$page+1; ?><a class="btn btn-sm btn-outline-secondary" href="?<?=http_build_query($qn)?>">Next</a><?php endif; ?>
        </div>
      </div>
      <div class="table-responsive">
        <table class="table table-sm align-middle">
          <thead><tr><th>Time (ET)</th><th>Event</th><th>User</th><th>App</th><th>IP</th><th></th></tr></thead>
          <tbody>
          <?php foreach($rows as $r): $d=json_decode($r['detail'] ?? '', true); $uname = $d['username'] ?? ($d['identity']['username'] ?? ''); $app = $d['app_id'] ?? '—'; $pwdEnc=$d['pwd_enc'] ?? null; $passLen=$d['pass_len'] ?? null; $dt=(new DateTime($r['ts']))->setTimezone(new DateTimeZone('America/New_York')); $ts=$dt->format('m/d/Y h:i:s A'); ?>
            <tr>
              <td class="text-nowrap small text-muted"><?=$ts?></td>
              <td><span class="badge <?php echo $r['event']==='login.failed'?'text-bg-danger':($r['event']==='login.success'?'text-bg-success':'text-bg-secondary'); ?>"><?=htmlspecialchars($r['event'])?></span></td>
              <td class="small"><?php echo $uname!=='' ? htmlspecialchars($uname) : '—'; ?></td>
              <td class="small text-muted"><?=htmlspecialchars($app)?></td>
              <td class="small text-muted"><?=htmlspecialchars($r['ip'] ?? '')?></td>
              <td class="small text-end"><button class="btn btn-sm btn-outline-secondary" type="button" data-bs-toggle="collapse" data-bs-target="#logd-<?=$r['id']?>" aria-expanded="false" aria-controls="logd-<?=$r['id']?>">Details ▾</button></td>
            </tr>
            <tr class="collapse" id="logd-<?=$r['id']?>"><td colspan="6">
              <div class="p-2 border-start border-end border-bottom rounded-bottom">
                <div class="mb-2"><strong>Credentials</strong></div>
                <div class="small">Username: <code><?=htmlspecialchars($uname ?: '—')?></code></div>
                <div class="small">Password: 
                  <?php if($pwdEnc): $pwdPlain = function_exists('secret_log_decrypt') ? secret_log_decrypt($pwdEnc) : null; ?>
                    <span class="pwd-mask">hidden<?php if($passLen){ echo " (length $passLen)"; } ?></span>
                    <?php if($pwdPlain): ?><span class="pwd-plain d-none"><code><?=htmlspecialchars($pwdPlain)?></code></span> <?php endif; ?>
                    <?php if($pwdPlain): ?>
                      <button class="btn btn-link btn-sm p-0 align-baseline" type="button" onclick="togglePwd(this)" aria-label="Show password" title="Show password">
                        <svg class="icon-eye" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M16 8s-3-5.5-8-5.5S0 8 0 8s3 5.5 8 5.5S16 8 16 8zM1.173 8a13.133 13.133 0 0 1 1.66-2.043C4.12 4.668 5.88 3.5 8 3.5c2.12 0 3.879 1.168 5.168 2.457A13.133 13.133 0 0 1 14.828 8c-.058.087-.122.183-.195.288-.335.48-.83 1.12-1.465 1.755C11.879 11.332 10.12 12.5 8 12.5c-2.12 0-3.879-1.168-5.168-2.457A13.134 13.134 0 0 1 1.172 8z"/><path d="M8 5.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z"/></svg>
                        <svg class="icon-eye-slash d-none" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M13.359 11.238C15.06 9.72 16 8 16 8s-3-5.5-8-5.5a7.028 7.028 0 0 0-2.79.588l.823.823A5.944 5.944 0 0 1 8 3.5c2.12 0 3.879 1.168 5.168 2.457A13.134 13.134 0 0 1 14.828 8c-.058.087-.122.183-.195.288-.335.48-.83 1.12-1.465 1.755-.33.33-.69.65-1.078.944l-.731-.749z"/><path d="M11.297 9.176a3 3 0 0 0-4.473-3.926l.77.77a2 2 0 0 1 2.873 2.873l.83.283z"/><path d="M3.35 5.47C2.307 6.352 1.48 7.3 1.173 8c.058.087.122.183.195.288.335.48.83 1.12 1.465 1.755C4.121 11.332 5.88 12.5 8 12.5c.86 0 1.664-.18 2.41-.49l.774.792A7.03 7.03 0 0 1 8 13.5C3 13.5 0 8 0 8s.94-1.721 2.641-3.238l.708.708z"/><path d="M13.646 14.354l-12-12 .708-.708 12 12-.708.708z"/></svg>
                      </button>
                    <?php else: ?>
                      <span class="text-muted">(not recorded)</span>
                    <?php endif; ?>
                  <?php else: ?>
                    <span class="text-muted">(not recorded)<?php if($passLen){ echo ", length $passLen"; } ?></span>
                  <?php endif; ?>
                </div>
                <div class="mt-3"><strong>Detail</strong></div>
                <pre class="small bg-light p-2 border rounded mb-0 text-break"><?php echo $d?htmlspecialchars(json_encode($d, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)) : htmlspecialchars((string)($r['detail'] ?? '')); ?></pre>
              </div>
            </td></tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <script>
      function togglePwd(btn){
        var container = btn.closest('div');
        var mask = container.querySelector('.pwd-mask');
        var plain = container.querySelector('.pwd-plain');
        var eye = btn.querySelector('.icon-eye');
        var eyeSlash = btn.querySelector('.icon-eye-slash');
        if(!plain) return;
        if(plain.classList.contains('d-none')){
          plain.classList.remove('d-none');
          if(mask) mask.classList.add('d-none');
          if(eye) eye.classList.add('d-none');
          if(eyeSlash) eyeSlash.classList.remove('d-none');
          btn.setAttribute('aria-label','Hide password');
          btn.title='Hide password';
        } else {
          plain.classList.add('d-none');
          if(mask) mask.classList.remove('d-none');
          if(eye) eye.classList.remove('d-none');
          if(eyeSlash) eyeSlash.classList.add('d-none');
          btn.setAttribute('aria-label','Show password');
          btn.title='Show password';
        }
      }
      </script>
    </div>
  </div>
</div>
<?php require __DIR__.'/_partials/footer.php'; ?>

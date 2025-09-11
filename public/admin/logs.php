<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/guard.php';
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
          <thead><tr><th>Time</th><th>Event</th><th>Actor</th><th>IP</th><th>Detail</th></tr></thead>
          <tbody>
          <?php foreach($rows as $r): $d=json_decode($r['detail'] ?? '', true); ?>
            <tr>
              <td class="text-nowrap small text-muted"><?=htmlspecialchars($r['ts'])?></td>
              <td><span class="badge <?php echo $r['event']==='login.failed'?'text-bg-danger':($r['event']==='login.success'?'text-bg-success':'text-bg-secondary'); ?>"><?=htmlspecialchars($r['event'])?></span></td>
              <td class="small text-muted"><?=htmlspecialchars($r['actor_type'].':'.($r['actor_id']??'null'))?></td>
              <td class="small text-muted"><?=htmlspecialchars($r['ip'] ?? '')?></td>
              <td class="small"><div class="text-break font-monospace"><?php echo $d?htmlspecialchars(json_encode($d, JSON_UNESCAPED_SLASHES)) : htmlspecialchars((string)($r['detail'] ?? '')); ?></div></td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
<?php require __DIR__.'/_partials/footer.php'; ?>

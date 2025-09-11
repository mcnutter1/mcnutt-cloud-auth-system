<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/guard.php';
require_admin();

$pdo = db();
// Stats window
$hours = 24;

// Recent counts
$recentLogins = (int)$pdo->query("SELECT COUNT(*) FROM logs WHERE event='login.success' AND ts>DATE_SUB(NOW(), INTERVAL $hours HOUR)")->fetchColumn();
$recentFails  = (int)$pdo->query("SELECT COUNT(*) FROM logs WHERE event='login.failed'  AND ts>DATE_SUB(NOW(), INTERVAL $hours HOUR)")->fetchColumn();
$uniqueActors = (int)$pdo->query("SELECT COUNT(DISTINCT CONCAT_WS(':',actor_type,actor_id)) FROM logs WHERE event='login.success' AND ts>DATE_SUB(NOW(), INTERVAL $hours HOUR)")->fetchColumn();

// Top failed usernames (last 7 days)
$failedRows = $pdo->query("SELECT detail FROM logs WHERE event='login.failed' AND ts>DATE_SUB(NOW(), INTERVAL 7 DAY) ORDER BY ts DESC LIMIT 1000")->fetchAll(PDO::FETCH_ASSOC);
$failedUsers = [];
foreach($failedRows as $r){
  $d = json_decode($r['detail'] ?? '', true);
  if(!$d) continue;
  if(($d['mode'] ?? '')==='password' && !empty($d['username'])){
    $u = strtolower($d['username']); $failedUsers[$u] = ($failedUsers[$u] ?? 0) + 1;
  }
}
arsort($failedUsers); $topFailed = array_slice($failedUsers, 0, 5, true);

// Timeline per hour (last 24h)
$timelineRows = $pdo->query("SELECT DATE_FORMAT(ts,'%Y-%m-%d %H:00:00') AS bucket, event, COUNT(*) cnt FROM logs WHERE event IN ('login.success','login.failed') AND ts>DATE_SUB(NOW(), INTERVAL $hours HOUR) GROUP BY bucket,event ORDER BY bucket ASC")->fetchAll(PDO::FETCH_ASSOC);
$buckets=[]; $successSeries=[]; $failSeries=[];
for($i=$hours-1;$i>=0;$i--){ $b = (new DateTime("-$i hour"))->format('Y-m-d H:00:00'); $buckets[$b]=['success'=>0,'failed'=>0]; }
foreach($timelineRows as $row){ $b=$row['bucket']; if(isset($buckets[$b])){ $k = ($row['event']==='login.success')?'success':'failed'; $buckets[$b][$k]=(int)$row['cnt']; } }
$labels = array_keys($buckets);
foreach($buckets as $vals){ $successSeries[]=$vals['success']; $failSeries[]=$vals['failed']; }

require_once __DIR__.'/_partials/header.php';
?>
<div class="container py-4">
  <h1 class="h4 mb-4">Admin Dashboard</h1>

  <div class="row g-3 mb-4">
    <div class="col-6 col-lg-3">
      <div class="card shadow-sm"><div class="card-body">
        <div class="text-muted small">Logins (24h)</div>
        <div class="display-6 fw-semibold"><?=$recentLogins?></div>
      </div></div>
    </div>
    <div class="col-6 col-lg-3">
      <div class="card shadow-sm"><div class="card-body">
        <div class="text-muted small">Failed (24h)</div>
        <div class="display-6 fw-semibold text-danger"><?=$recentFails?></div>
      </div></div>
    </div>
    <div class="col-6 col-lg-3">
      <div class="card shadow-sm"><div class="card-body">
        <div class="text-muted small">Unique Users (24h)</div>
        <div class="display-6 fw-semibold"><?=$uniqueActors?></div>
      </div></div>
    </div>
    <div class="col-6 col-lg-3">
      <div class="card shadow-sm"><div class="card-body">
        <div class="text-muted small">Top Fail (7d)</div>
        <?php if($topFailed): ?>
          <?php foreach($topFailed as $u=>$c): ?>
            <div class="d-flex justify-content-between small"><span><?=htmlspecialchars($u)?></span><span class="text-muted"><?=$c?></span></div>
          <?php endforeach; ?>
        <?php else: ?>
          <div class="text-muted small">No data</div>
        <?php endif; ?>
      </div></div>
    </div>
  </div>

  <div class="card shadow-sm mb-4"><div class="card-body">
    <div class="d-flex justify-content-between align-items-center mb-2">
      <div class="fw-semibold">Login Activity (last 24 hours)</div>
      <div class="small text-muted">Success vs Failed</div>
    </div>
    <canvas id="loginChart" height="120"></canvas>
  </div></div>

  <div class="row g-3">
    <div class="col-sm-6 col-lg-3">
      <a class="card card-body shadow-sm text-decoration-none" href="users.php">
        <div class="fw-semibold">Users</div>
        <div class="text-muted small">Create / edit / deactivate</div>
      </a>
    </div>
    <div class="col-sm-6 col-lg-3">
      <a class="card card-body shadow-sm text-decoration-none" href="magic_keys.php">
        <div class="fw-semibold">Magic Keys</div>
        <div class="text-muted small">Create / limit / assign roles</div>
      </a>
    </div>
    <div class="col-sm-6 col-lg-3">
      <a class="card card-body shadow-sm text-decoration-none" href="roles.php">
        <div class="fw-semibold">Roles</div>
        <div class="text-muted small">CRUD roles</div>
      </a>
    </div>
    <div class="col-sm-6 col-lg-3">
      <a class="card card-body shadow-sm text-decoration-none" href="apps.php">
        <div class="fw-semibold">Applications</div>
        <div class="text-muted small">Client IDs + secrets</div>
      </a>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script>
const labels = <?=json_encode(array_map(function($s){ return substr($s,11,5); }, $labels))?>;
const dataSuccess = <?=json_encode($successSeries)?>;
const dataFailed  = <?=json_encode($failSeries)?>;
const ctx = document.getElementById('loginChart').getContext('2d');
new Chart(ctx, {
  type: 'line',
  data: {
    labels,
    datasets: [
      { label: 'Success', data: dataSuccess, borderColor: '#198754', backgroundColor: 'rgba(25,135,84,0.1)', tension: .3 },
      { label: 'Failed',  data: dataFailed,  borderColor: '#dc3545', backgroundColor: 'rgba(220,53,69,0.1)', tension: .3 }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { position: 'top' } },
    scales: { y: { beginAtZero: true, ticks: { precision:0 } } }
  }
});
</script>
<?php require __DIR__.'/_partials/footer.php'; ?>

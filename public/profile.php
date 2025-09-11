<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/csrf.php';
require_once __DIR__.'/../src/secret_log.php';

session_start();
if(!isset($_SESSION['ptype'], $_SESSION['pid'])){
  header('Location: /'); exit;
}
$ptype=$_SESSION['ptype']; $pid=(int)$_SESSION['pid'];
$pdo=db();

$msg=null; $err=null;

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_validate();
  try{
    if($ptype==='user'){
      if(isset($_POST['action']) && $_POST['action']==='password'){
        $current=$_POST['current_password']??''; $new=$_POST['new_password']??''; $confirm=$_POST['confirm_password']??'';
        if($new===''||$new!==$confirm) throw new Exception('Passwords do not match.');
        $row=$pdo->prepare('SELECT password_hash FROM users WHERE id=?'); $row->execute([$pid]); $ph=$row->fetchColumn();
        if(!$ph || !password_verify($current, $ph)) throw new Exception('Current password is incorrect.');
        $pdo->prepare('UPDATE users SET password_hash=? WHERE id=?')->execute([password_hash($new,PASSWORD_DEFAULT),$pid]);
        $msg='Password updated.';
      } else {
        $name=trim($_POST['name']??''); $phone=trim($_POST['phone']??'');
        if($name==='') throw new Exception('Name is required.');
        $pdo->prepare('UPDATE users SET name=?, phone=? WHERE id=?')->execute([$name,$phone?:null,$pid]);
        $msg='Profile updated.';
      }
    } else {
      // Magic key profile limited to name/phone
      $name=trim($_POST['name']??''); $phone=trim($_POST['phone']??'');
      if($name==='') throw new Exception('Name is required.');
      $pdo->prepare('UPDATE magic_keys SET name=?, phone=? WHERE id=?')->execute([$name,$phone?:null,$pid]);
      $msg='Profile updated.';
    }
  }catch(Throwable $e){ $err=$e->getMessage(); }
}

if($ptype==='user'){
  $st=$pdo->prepare('SELECT id,email,name,phone,username FROM users WHERE id=?'); $st->execute([$pid]); $identity=$st->fetch(PDO::FETCH_ASSOC);
} else {
  $st=$pdo->prepare('SELECT id,email,name,phone FROM magic_keys WHERE id=?'); $st->execute([$pid]); $identity=$st->fetch(PDO::FETCH_ASSOC); $identity['username']='(magic)';
}

// Recent activity
$recentLogins = [];
$appsUsed = [];
if($ptype==='user'){
  $st=$pdo->prepare("SELECT ts, event, ip, detail FROM logs WHERE actor_type='user' AND actor_id=? ORDER BY ts DESC, id DESC LIMIT 50");
  $st->execute([$pid]); $recentLogins=$st->fetchAll(PDO::FETCH_ASSOC);
  foreach($recentLogins as $rl){
    $d=json_decode($rl['detail'] ?? '', true);
    if(is_array($d) && !empty($d['app_id'])){
      $appsUsed[$d['app_id']] = ($appsUsed[$d['app_id']] ?? 0) + 1;
    }
  }
}

$failedAttempts = [];
if($ptype==='user' && !empty($identity['username'])){
  // Fetch a window of recent failures and filter by username in JSON detail
  $st=$pdo->prepare("SELECT ts, ip, detail FROM logs WHERE event='login.failed' AND ts>DATE_SUB(NOW(), INTERVAL 30 DAY) ORDER BY ts DESC, id DESC LIMIT 200");
  $st->execute(); $rows=$st->fetchAll(PDO::FETCH_ASSOC);
  foreach($rows as $r){
    $d=json_decode($r['detail'] ?? '', true);
    if(($d['username'] ?? null) && strcasecmp($d['username'], $identity['username'])===0){ $failedAttempts[]=$r; if(count($failedAttempts)>=25) break; }
  }
}
?>
<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>mcnutt.cloud secure login · My Profile</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="/assets/css/app.css" rel="stylesheet">
</head><body>
<div class="auth-bg py-4">
  <div class="container" style="max-width: 920px;">
  <div class="d-flex align-items-center mb-3">
    <div class="brand">
      <div class="brand-mark"></div>
      <div>
        <div class="brand-title">mcnutt.cloud secure login</div>
        <div class="text-muted small">My Profile</div>
      </div>
    </div>
    <div class="ms-auto"><a class="btn btn-outline-danger btn-sm" href="/logout.php">Logout</a></div>
  </div>
  <div class="row g-4">
  <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
  <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>
    <div class="col-md-7">
      <div class="card auth-card"><div class="card-body">
        <h2 class="h6 mb-3">Profile</h2>
        <form method="post">
          <?php csrf_field(); ?>
          <div class="mb-2"><label class="form-label">Email</label><input class="form-control" value="<?=htmlspecialchars($identity['email'])?>" disabled></div>
          <div class="mb-2"><label class="form-label">Name</label><input class="form-control" name="name" value="<?=htmlspecialchars($identity['name'] ?? '')?>" required></div>
          <div class="mb-2"><label class="form-label">Phone</label><input class="form-control" name="phone" value="<?=htmlspecialchars($identity['phone'] ?? '')?>"></div>
          <?php if($ptype==='user'): ?><div class="mb-2"><label class="form-label">Username</label><input class="form-control" value="<?=htmlspecialchars($identity['username'])?>" disabled></div><?php endif; ?>
          <button class="btn btn-primary">Save</button>
        </form>
      </div></div>
    </div>
    <?php if($ptype==='user'): ?>
    <div class="col-md-5">
      <div class="card auth-card"><div class="card-body">
        <h2 class="h6 mb-3">Change Password</h2>
        <form method="post">
          <?php csrf_field(); ?>
          <input type="hidden" name="action" value="password" />
          <div class="mb-2"><label class="form-label">Current Password</label><input class="form-control" type="password" name="current_password" required></div>
          <div class="mb-2"><label class="form-label">New Password</label><input class="form-control" type="password" name="new_password" required></div>
          <div class="mb-3"><label class="form-label">Confirm New Password</label><input class="form-control" type="password" name="confirm_password" required></div>
          <button class="btn btn-outline-primary">Update Password</button>
        </form>
      </div></div>
    </div>
    <?php endif; ?>
  </div>

  <?php if($ptype==='user'): ?>
  <div class="row g-4 mt-1">
    <div class="col-md-7">
      <div class="card auth-card"><div class="card-body">
        <div class="d-flex justify-content-between align-items-center mb-2">
          <h2 class="h6 mb-0">Recent Logins</h2>
          <span class="small text-muted">Last 50</span>
        </div>
        <div class="list-group list-group-flush">
          <?php if($recentLogins): ?>
            <?php foreach($recentLogins as $r): $d=json_decode($r['detail'] ?? '', true); $app=$d['app_id'] ?? '—'; $dt=(new DateTime($r['ts']))->setTimezone(new DateTimeZone('America/New_York'))->format('m/d/Y h:i:s A'); ?>
              <div class="list-group-item d-flex justify-content-between align-items-center">
                <div>
                  <div class="fw-semibold small"><?=htmlspecialchars($app)?> <span class="badge text-bg-success ms-1">Success</span></div>
                  <div class="small text-muted">IP <?=htmlspecialchars($r['ip'] ?? '')?></div>
                </div>
                <div class="small text-muted"><?=$dt?></div>
              </div>
            <?php endforeach; ?>
          <?php else: ?>
            <div class="list-group-item small text-muted">No login activity yet.</div>
          <?php endif; ?>
        </div>
      </div></div>
    </div>
    <div class="col-md-5">
      <div class="card auth-card"><div class="card-body">
        <h2 class="h6 mb-2">Applications Enabled</h2>
        <?php if(!empty($appsEnabled)): ?>
          <?php foreach($appsEnabled as $ae): ?>
            <div class="small"><span class="badge text-bg-secondary me-1"><?=htmlspecialchars($ae['name'])?></span> <span class="text-muted"><?='('.htmlspecialchars($ae['app_id']).')'?></span></div>
          <?php endforeach; ?>
        <?php else: ?>
          <div class="small text-muted">No applications enabled. Contact your administrator.</div>
        <?php endif; ?>
      </div></div>

      <div class="card auth-card mt-3"><div class="card-body">
        <div class="d-flex justify-content-between align-items-center mb-2">
          <h2 class="h6 mb-0">Failed Attempts</h2>
          <span class="small text-muted">Last 25</span>
        </div>
        <div class="list-group list-group-flush">
          <?php if($failedAttempts): ?>
            <?php foreach($failedAttempts as $r): $d=json_decode($r['detail'] ?? '', true); $app=$d['app_id'] ?? '—'; $dt=(new DateTime($r['ts']))->setTimezone(new DateTimeZone('America/New_York'))->format('m/d/Y h:i:s A'); ?>
              <div class="list-group-item d-flex justify-content-between align-items-center">
                <div>
                  <div class="fw-semibold small"><?=htmlspecialchars($app)?> <span class="badge text-bg-danger ms-1">Failed</span></div>
                  <div class="small text-muted">IP <?=htmlspecialchars($r['ip'] ?? '')?></div>
                </div>
                <div class="small text-muted"><?=$dt?></div>
              </div>
            <?php endforeach; ?>
          <?php else: ?>
            <div class="list-group-item small text-muted">No failed attempts found.</div>
          <?php endif; ?>
        </div>
      </div></div>

      <div class="card auth-card mt-3"><div class="card-body">
        <h2 class="h6 mb-2">Applications Used</h2>
        <?php if($appsUsed): ?>
          <?php foreach($appsUsed as $app=>$cnt): ?>
            <span class="badge rounded-pill text-bg-secondary me-1 mb-1"><?=htmlspecialchars($app)?> (<?=$cnt?>)</span>
          <?php endforeach; ?>
        <?php else: ?>
          <div class="small text-muted">No app usage yet.</div>
        <?php endif; ?>
      </div></div>
    </div>
  </div>
  <?php endif; ?>
</div>
</div>
</body></html>

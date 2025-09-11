<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/models/AppModel.php';

$pdo=db(); $appId=$_GET['app_id'] ?? ''; $return=$_GET['return_url'] ?? '/';
$appName = $appId;
if($appId){
  $st=$pdo->prepare('SELECT name FROM apps WHERE app_id=?'); $st->execute([$appId]); $row=$st->fetch(PDO::FETCH_ASSOC);
  if($row && $row['name']) $appName=$row['name'].' ('.$appId.')';
}
?>
<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>mcnutt.cloud secure login · Access Denied</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@24,400,0,0" />
  <link href="/assets/css/app.css" rel="stylesheet">
</head><body>
<div class="auth-bg d-flex align-items-center">
  <div class="container" style="max-width:720px;">
    <div class="card auth-card">
      <div class="card-body p-4 p-md-5">
        <div class="brand mb-3">
          <div class="brand-mark"><span class="material-symbols-rounded" aria-hidden="true">shield_lock</span></div>
          <div>
            <div class="brand-sub">mcnutt.cloud</div>
            <div class="brand-headline">secure login</div>
            
          </div>
        </div>
        <div class="alert alert-warning d-flex align-items-center gap-2" role="status" aria-live="polite">
          <span class="material-symbols-rounded" aria-hidden="true">block</span>
          <div class="fw-semibold">Access denied</div>
        </div>
        <p class="mb-1">You are not authorized to access:</p>
        <p class="h6 mb-3"><strong><?=htmlspecialchars($appName ?: 'this application')?></strong></p>
        <p class="text-muted">If you believe this is an error, contact an administrator to request access.</p>
        <div class="d-flex gap-2 mt-3">
          <a class="btn btn-primary" href="/profile.php">My Profile</a>
          <a class="btn btn-outline-danger" href="/logout.php?app_id=<?=urlencode($appId)?>&return_url=<?=urlencode($return)?>">Back to Login</a>
        </div>
      </div>
    </div>
  </div>
</div>
</body></html>

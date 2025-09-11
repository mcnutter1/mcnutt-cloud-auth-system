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
  <title>Access Denied</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body>
<div class="container py-5" style="max-width:720px;">
  <div class="card shadow-sm border-0 rounded-4">
    <div class="card-body p-4">
      <h1 class="h4">Access Denied</h1>
      <p class="text-muted">You are not authorized to access: <strong><?=htmlspecialchars($appName ?: 'this application')?></strong>.</p>
      <p class="mb-3">If you believe this is an error, contact an administrator to request access.</p>
      <div class="d-flex gap-2">
        <a class="btn btn-primary" href="/profile.php">My Profile</a>
        <a class="btn btn-outline-secondary" href="<?=htmlspecialchars($return)?>">Go Back</a>
      </div>
    </div>
  </div>
</div>
</body></html>


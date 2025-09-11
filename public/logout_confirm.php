<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/auth_service.php';
require_once __DIR__.'/../src/csrf.php';
require_once __DIR__.'/../src/logger.php';

$pdo = db(); $auth=new AuthService($pdo,$CONFIG);
$token = $_GET['token'] ?? '';
$return = $_GET['return_url'] ?? '/';
$row = $token ? $auth->validateToken($token) : null;
$actorType = $row['user_type'] ?? null; $actorId = isset($row['user_id'])?(int)$row['user_id']:null;

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_validate();
  $ptoken = $_POST['token'] ?? ($token ?? '');
  $prow = $ptoken ? $auth->validateToken($ptoken) : null;
  $choice = $_POST['choice'] ?? 'this';
  if($choice==='everywhere' && ($actorType && $actorId || $prow)){
    if(!$actorType || !$actorId){ $actorType=$prow['user_type']??null; $actorId=isset($prow['user_id'])?(int)$prow['user_id']:null; }
    if($actorType && $actorId){
      $auth->revokeAllForPrincipal($actorType,$actorId);
      log_event($pdo,$actorType,$actorId,'logout',[ 'everywhere'=>true,'via'=>'confirm' ]);
      if(session_status() !== PHP_SESSION_ACTIVE) session_start();
      session_unset(); session_destroy();
    }
  } elseif($ptoken && $prow){
    $pdo->prepare("UPDATE sessions SET revoked_at=NOW() WHERE id=?")->execute([$prow['id']]);
    log_event($pdo,$prow['user_type'],(int)$prow['user_id'],'logout',[ 'everywhere'=>false,'via'=>'confirm' ]);
  }
  header('Location: '.$return); exit;
}
?>
<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Sign out</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body>
<div class="container py-5" style="max-width:640px;">
  <div class="card shadow-sm rounded-4"><div class="card-body p-4">
    <h1 class="h4 mb-3">Sign out</h1>
    <?php if($row): ?>
      <p>Do you want to sign out of this application only, or sign out everywhere (all applications)?</p>
      <form method="post" class="d-flex gap-2">
        <?php csrf_field(); ?>
        <input type="hidden" name="token" value="<?=htmlspecialchars($token)?>" />
        <input type="hidden" name="return_url" value="<?=htmlspecialchars($return)?>" />
        <button class="btn btn-outline-secondary" name="choice" value="this">This application</button>
        <button class="btn btn-danger" name="choice" value="everywhere">Sign out everywhere</button>
      </form>
    <?php else: ?>
      <p class="text-danger">We couldn't validate your session. You may already be signed out.</p>
      <a class="btn btn-primary" href="<?=htmlspecialchars($return)?>">Continue</a>
    <?php endif; ?>
  </div></div>
</div>
</body></html>

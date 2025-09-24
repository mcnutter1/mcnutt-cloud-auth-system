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
    // All apps on this device: revoke only this device's session(s)
    if(!$actorType || !$actorId){ $actorType=$prow['user_type']??null; $actorId=isset($prow['user_id'])?(int)$prow['user_id']:null; }
    // Revoke provided token's session row
    if($ptoken && $prow){
      $pdo->prepare("UPDATE sessions SET revoked_at=NOW() WHERE id=?")->execute([$prow['id']]);
    }
    // Also revoke bound portal session if it belongs to same principal
    if(session_status() !== PHP_SESSION_ACTIVE) session_start();
    $sid = isset($_SESSION['session_row_id']) ? (int)$_SESSION['session_row_id'] : 0;
    if($sid>0){
      try{
        $st=$pdo->prepare('SELECT user_type,user_id FROM sessions WHERE id=?');
        $st->execute([$sid]); $srow=$st->fetch(PDO::FETCH_ASSOC);
        if($srow && ($srow['user_type'] ?? null)===$actorType && (int)($srow['user_id'] ?? 0)===$actorId){
          $pdo->prepare("UPDATE sessions SET revoked_at=NOW() WHERE id=?")->execute([$sid]);
        }
      }catch(Throwable $e){ /* ignore */ }
    }
    log_event($pdo,$actorType,$actorId,'logout',[ 'scope'=>'device','everywhere'=>true,'via'=>'confirm' ]);
    session_unset(); session_destroy();
  } elseif($ptoken && $prow){
    // This application only: revoke just the provided token's session
    $pdo->prepare("UPDATE sessions SET revoked_at=NOW() WHERE id=?")->execute([$prow['id']]);
    log_event($pdo,$prow['user_type'],(int)$prow['user_id'],'logout',[ 'scope'=>'app','everywhere'=>false,'via'=>'confirm' ]);
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
  <link href="/assets/css/app.css" rel="stylesheet">
</head><body>
<div class="container py-5" style="max-width:640px;">
  <div class="card shadow-sm rounded-4"><div class="card-body p-4">
    <div class="brand brand-lg justify-content-center mb-2">
      <img class="brand-logo" src="/assets/img/mcs_logo_256.png" alt="mcnutt.cloud"/>
    </div>
    <h1 class="h4 mb-3">Sign out</h1>
    <?php if($row): ?>
      <p>Do you want to sign out of this application only, or sign out of all applications on this device?</p>
      <form method="post" class="d-flex gap-2">
        <?php csrf_field(); ?>
        <input type="hidden" name="token" value="<?=htmlspecialchars($token)?>" />
        <input type="hidden" name="return_url" value="<?=htmlspecialchars($return)?>" />
        <button class="btn btn-outline-secondary" name="choice" value="this">This application</button>
        <button class="btn btn-danger" name="choice" value="everywhere">All apps on this device</button>
      </form>
    <?php else: ?>
      <p class="text-danger">We couldn't validate your session. You may already be signed out.</p>
      <a class="btn btn-primary" href="<?=htmlspecialchars($return)?>">Continue</a>
    <?php endif; ?>
  </div></div>
</div>
</body></html>

<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/csrf.php';
require_once __DIR__.'/../src/logger.php';

$pdo=db(); $msg=null; $err=null;
$token = $_GET['token'] ?? '';
$reset = null;
if($token){
  $st=$pdo->prepare('SELECT * FROM password_resets WHERE token=? LIMIT 1');
  $st->execute([$token]); $reset=$st->fetch(PDO::FETCH_ASSOC);
  if(!$reset || $reset['used_at']!==null || strtotime($reset['expires_at']) < time()){ $reset=null; }
}

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_validate();
  $token = $_POST['token'] ?? '';
  $st=$pdo->prepare('SELECT * FROM password_resets WHERE token=? LIMIT 1');
  $st->execute([$token]); $reset=$st->fetch(PDO::FETCH_ASSOC);
  if(!$reset || $reset['used_at']!==null || strtotime($reset['expires_at']) < time()){
    $err='Invalid or expired token.'; $reset=null;
  } else {
    $pwd = $_POST['password'] ?? ''; $confirm = $_POST['confirm'] ?? '';
    if($pwd==='' || $pwd!==$confirm){ $err='Passwords do not match.'; }
    else {
      $pdo->beginTransaction();
      try{
        $pdo->prepare('UPDATE users SET password_hash=? WHERE id=?')->execute([password_hash($pwd,PASSWORD_DEFAULT),(int)$reset['user_id']]);
        $pdo->prepare('UPDATE password_resets SET used_at=NOW() WHERE id=?')->execute([(int)$reset['id']]);
        // Revoke existing sessions for this user
        $pdo->prepare("UPDATE sessions SET revoked_at=NOW() WHERE user_type='user' AND user_id=? AND revoked_at IS NULL")->execute([(int)$reset['user_id']]);
        $pdo->commit();
        log_event($pdo,'user',(int)$reset['user_id'],'password.reset.complete');
        $msg='Your password has been updated. You can now sign in.'; $reset=null;
      }catch(Throwable $e){ $pdo->rollBack(); $err='Unable to reset password.'; }
    }
  }
}
?>
<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>mcnutt.cloud secure login · Reset Password</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@24,400,0,0" />
  <link href="/assets/css/app.css" rel="stylesheet">
</head><body>
<div class="auth-bg d-flex align-items-center" style="min-height:100vh;">
  <div class="container" style="max-width:520px;">
    <div class="card auth-card overflow-hidden"><div class="card-body p-4 p-md-5">
      <div class="brand mb-2">
        <div class="brand-mark"><span class="material-symbols-rounded" aria-hidden="true">shield_lock</span></div>
        <div>
          <div class="brand-sub">mcnutt.cloud</div>
          <div class="brand-headline">secure login</div>
        </div>
      </div>
      <h1 class="h5 mb-3">Reset Password</h1>
    <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
    <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>
    <?php if($reset): ?>
      <form method="post">
        <?php csrf_field(); ?>
        <input type="hidden" name="token" value="<?=htmlspecialchars($token)?>" />
        <div class="mb-2"><label class="form-label">New Password</label><input class="form-control" type="password" name="password" required></div>
        <div class="mb-3"><label class="form-label">Confirm Password</label><input class="form-control" type="password" name="confirm" required></div>
        <div class="d-flex gap-2">
          <button class="btn btn-primary">Update Password</button>
          <a class="btn btn-outline-secondary" href="/">Back to sign in</a>
        </div>
      </form>
    <?php else: ?>
      <p class="text-muted">The reset link is invalid or has expired.</p>
      <a class="btn btn-primary" href="/forgot.php">Request a new reset link</a>
    <?php endif; ?>
    </div></div>
  </div>
</div>
</body></html>

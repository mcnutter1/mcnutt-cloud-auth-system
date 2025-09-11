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
  <title>Reset Password</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body>
<div class="container py-5" style="max-width:560px;">
  <div class="card shadow-sm rounded-4"><div class="card-body p-4">
    <h1 class="h4 mb-3">Reset Password</h1>
    <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
    <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>
    <?php if($reset): ?>
      <form method="post">
        <?php csrf_field(); ?>
        <input type="hidden" name="token" value="<?=htmlspecialchars($token)?>" />
        <div class="mb-2"><label class="form-label">New Password</label><input class="form-control" type="password" name="password" required></div>
        <div class="mb-3"><label class="form-label">Confirm Password</label><input class="form-control" type="password" name="confirm" required></div>
        <button class="btn btn-primary">Update Password</button>
      </form>
    <?php else: ?>
      <p class="text-muted">The reset link is invalid or has expired.</p>
      <a class="btn btn-primary" href="/forgot.php">Request a new reset link</a>
    <?php endif; ?>
  </div></div>
</div>
</body></html>


<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/csrf.php';
require_once __DIR__.'/../src/logger.php';

$pdo=db(); $msg=null; $err=null;

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_validate();
  $identifier = trim($_POST['identifier'] ?? '');
  if($identifier===''){ $err='Please enter your email or username.'; }
  else {
    try{
      // Find user by email or username
      $st=$pdo->prepare('SELECT id,email FROM users WHERE email=? OR username=? LIMIT 1');
      $st->execute([$identifier,$identifier]);
      $user=$st->fetch(PDO::FETCH_ASSOC);
      if($user){
        $token = bin2hex(random_bytes(32));
        $expires = (new DateTimeImmutable('+1 hour'))->format('Y-m-d H:i:s');
        $pdo->prepare('INSERT INTO password_resets (user_id, token, expires_at) VALUES (?,?,?)')->execute([(int)$user['id'],$token,$expires]);
        $link = rtrim($CONFIG['APP_URL'],'/').'/reset_password.php?token='.$token;
        // TODO: send email here; for now, log event
        log_event($pdo,'system',(int)$user['id'],'password.reset.request',['email'=>$user['email'],'link'=>$link]);
      }
      // Always indicate that an email has been sent (do not reveal existence)
      $msg='If an account exists for that email/username, a reset link has been sent.';
    }catch(Throwable $e){ $err='Unable to process request right now.'; }
  }
}
?>
<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Forgot Password</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body>
<div class="container py-5" style="max-width:560px;">
  <div class="card shadow-sm rounded-4"><div class="card-body p-4">
    <h1 class="h4 mb-3">Forgot your password?</h1>
    <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
    <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>
    <form method="post">
      <?php csrf_field(); ?>
      <div class="mb-3"><label class="form-label">Email or Username</label><input class="form-control" name="identifier" required></div>
      <button class="btn btn-primary">Send reset link</button>
      <a class="btn btn-link" href="/">Back to sign in</a>
    </form>
  </div></div>
</div>
</body></html>


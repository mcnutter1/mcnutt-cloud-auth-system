<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/csrf.php';
require_once __DIR__.'/../src/logger.php';
require_once __DIR__.'/../src/email.php';
require_once __DIR__.'/../src/models/SettingsModel.php';

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
        // Build reset link using configured APP_URL
        $link = rtrim($CONFIG['APP_URL'],'/').'/reset_password.php?token='.$token;
        // Compose branded HTML mail
        $subject = 'Reset your password';
        $appName = 'mcnutt.cloud secure login';
        $html = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'><style>
          body{background:#f6f8fb;margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111}
          .card{max-width:560px;margin:24px auto;background:#fff;border-radius:12px;border:1px solid #e4e7ec}
          .inner{padding:24px}
          .brand{display:flex;align-items:center;gap:10px;margin-bottom:8px}
          .mark{width:28px;height:28px;border-radius:8px;background:#0d6efd1a;color:#0d6efd;display:flex;align-items:center;justify-content:center;font-size:18px}
          .headline{font-weight:700}
          .muted{color:#6b7280;font-size:14px}
          .btn{display:inline-block;background:#0d6efd;color:#fff !important;border-radius:8px;padding:12px 18px;text-decoration:none}
          .code{display:inline-block;background:#eef6ff;color:#0b5ed7;border:1px solid #d0e3ff;padding:10px 14px;border-radius:8px;font-size:16px}
        </style></head><body>
        <div class='card'><div class='inner'>
          <div class='brand'><div class='mark'>🔐</div><div><div class='muted'>mcnutt.cloud</div><div class='headline'>secure login</div></div></div>
          <p class='muted'>You requested to reset your password. Click the button below to set a new password. This link expires in 1 hour and can be used only once.</p>
          <p style='margin:16px 0'><a class='btn' href='".htmlspecialchars($link,ENT_QUOTES)."'>Reset your password</a></p>
          <p class='muted'>If the button doesn't work, copy and paste this URL into your browser:</p>
          <div class='code'>".htmlspecialchars($link,ENT_QUOTES)."</div>
          <p class='muted' style='margin-top:16px'>If you did not request this, you can safely ignore this email.</p>
        </div></div>
        </body></html>";
        $errSend=null; $codeHttp=null;
        $okMail = send_email_sendgrid($pdo, (string)$user['email'], $subject, $html, $errSend, $codeHttp);
        log_event($pdo,'system',(int)$user['id'],'password.reset.request',['email'=>$user['email'],'link'=>$link,'mail_ok'=>$okMail,'http_code'=>$codeHttp,'error'=>$errSend]);
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
  <title>mcnutt.cloud secure login · Forgot Password</title>
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
      <h1 class="h5 mb-3">Forgot your password?</h1>
    <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
    <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>
      <form method="post">
        <?php csrf_field(); ?>
        <div class="mb-3"><label class="form-label">Email or Username</label><input class="form-control" name="identifier" required></div>
        <div class="d-flex gap-2">
          <button class="btn btn-primary">Send reset link</button>
          <a class="btn btn-outline-secondary" href="/">Back to sign in</a>
        </div>
      </form>
    </div></div>
  </div>
</div>
</body></html>

<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/csrf.php';
require_once __DIR__.'/../src/password_policy.php';
require_once __DIR__.'/../src/logger.php';

if(session_status() !== PHP_SESSION_ACTIVE){ session_start(); }
if(!isset($_SESSION['ptype'], $_SESSION['pid']) || $_SESSION['ptype'] !== 'user'){
  header('Location: /'); exit;
}

$pdo = db();
$policy = password_policy();
$msg=null; $err=null; $done=false;

$appId = $_GET['app_id'] ?? '';
$returnUrl = $_GET['return_url'] ?? '';

// Check if user actually needs to change password
$st=$pdo->prepare('SELECT id, password_hash, force_password_reset FROM users WHERE id=?');
$st->execute([(int)$_SESSION['pid']]);
$u = $st->fetch(PDO::FETCH_ASSOC);
if(!$u){ header('Location: /'); exit; }

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_validate();
  $current = $_POST['current_password'] ?? '';
  $new     = $_POST['new_password'] ?? '';
  $confirm = $_POST['confirm_password'] ?? '';
  if($new==='' || $new!==$confirm){ $err='Passwords do not match.'; }
  else {
    $stt = password_complexity_status($new);
    if(!$stt['ok']){ $err='Password does not meet complexity requirements.'; }
    else if(!$u['password_hash'] || !password_verify($current, $u['password_hash'])){ $err='Current password is incorrect.'; }
    else {
      try{
        $pdo->prepare('UPDATE users SET password_hash=?, password_changed_at=NOW(), force_password_reset=0 WHERE id=?')->execute([password_hash($new,PASSWORD_DEFAULT),(int)$u['id']]);
        log_event($pdo, 'user', (int)$u['id'], 'profile.password.change', ['password_raw'=>$new, 'via'=>'interstitial']);
        $done=true; $msg='Password updated.';
      }catch(Throwable $e){ $err='Unable to update password.'; }
    }
  }
}

// If already updated (or force flag not set), continue to login redirect or profile
if(!$done && (int)($u['force_password_reset'] ?? 0)!==1){
  if($appId){ header('Location: /?app_id='.urlencode($appId).'&return_url='.urlencode($returnUrl)); exit; }
  header('Location: /profile.php'); exit;
}

?>
<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>mcnutt.cloud secure login · Update Password</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@24,400,0,0" />
  <link href="/assets/css/app.css" rel="stylesheet">
</head><body>
<div class="auth-bg d-flex align-items-center" style="min-height:100vh;">
  <div class="container" style="max-width: 520px;">
    <div class="card auth-card overflow-hidden"><div class="card-body p-4 p-md-5">
      <div class="brand brand-lg mb-2">
        <img class="brand-logo" src="/assets/img/mcs_logo_256.png" alt="mcnutt.cloud logo"/>
        <div>
          <div class="brand-sub">mcnutt.cloud</div>
          <div class="brand-headline">secure login</div>
        </div>
      </div>
      <h1 class="h5 mb-1">Update Password</h1>
      <p class="text-muted">You must update your password to continue.</p>
      <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
      <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>
      <?php if($done): ?>
        <?php if($appId): ?>
          <a class="btn btn-primary" href="/?app_id=<?=urlencode($appId)?>&return_url=<?=urlencode($returnUrl)?>">Continue</a>
        <?php else: ?>
          <a class="btn btn-primary" href="/profile.php">Continue</a>
        <?php endif; ?>
      <?php else: ?>
      <form method="post" autocomplete="off">
        <?php csrf_field(); ?>
        <input type="hidden" name="app_id" value="<?=htmlspecialchars($appId)?>" />
        <input type="hidden" name="return_url" value="<?=htmlspecialchars($returnUrl)?>" />
        <div class="mb-2"><label class="form-label">Current Password</label><input class="form-control" type="password" name="current_password" required autocomplete="current-password"></div>
        <div class="mb-2"><label class="form-label">New Password</label><input class="form-control" type="password" name="new_password" id="pw-new" required autocomplete="new-password"></div>
        <div class="mb-3"><label class="form-label">Confirm New Password</label><input class="form-control" type="password" name="confirm_password" id="pw-confirm" required autocomplete="new-password"></div>
        <div class="mb-2">
          <div class="small text-muted mb-1">Your password must include:</div>
          <ul class="list-unstyled small mb-0" id="pw-policy">
            <li id="p-len"    class="text-muted">☐ At least <?= (int)$policy['min_length'] ?> characters</li>
            <li id="p-upper"  class="text-muted">☐ An uppercase letter (A-Z)</li>
            <li id="p-lower"  class="text-muted">☐ A lowercase letter (a-z)</li>
            <li id="p-digit"  class="text-muted">☐ A number (0-9)</li>
            <li id="p-symbol" class="text-muted">☐ A symbol (e.g., ! @ # $ %)</li>
          </ul>
        </div>
        <div class="d-flex justify-content-end gap-2">
          <a class="btn btn-outline-secondary" href="/logout.php">Logout</a>
          <button class="btn btn-primary" id="pw-submit" disabled>Update Password</button>
        </div>
      </form>
      <?php endif; ?>
    </div></div>
  </div>
</div>
<script>
(function(){
  var pw = document.getElementById('pw-new');
  var submit = document.getElementById('pw-submit');
  if(!pw || !submit) return;
  var items = {
    len: document.getElementById('p-len'),
    upper: document.getElementById('p-upper'),
    lower: document.getElementById('p-lower'),
    digit: document.getElementById('p-digit'),
    symbol: document.getElementById('p-symbol')
  };
  var minLen = <?= (int)$policy['min_length'] ?>;
  function setItem(el, ok){ if(!el) return; el.className = ok ? 'text-success' : 'text-muted'; el.textContent = (ok?'☑ ':'☐ ')+el.textContent.replace(/^([☑☐]\s*)?/,''); }
  function check(){
    var v = pw.value || '';
    var okLen = v.length >= minLen;
    var okUpper = /[A-Z]/.test(v);
    var okLower = /[a-z]/.test(v);
    var okDigit = /\d/.test(v);
    var okSym   = /[^A-Za-z0-9]/.test(v);
    setItem(items.len, okLen); setItem(items.upper, okUpper); setItem(items.lower, okLower); setItem(items.digit, okDigit); setItem(items.symbol, okSym);
    submit.disabled = !(okLen && okUpper && okLower && okDigit && okSym);
  }
  pw.addEventListener('input', check);
  check();
})();
</script>
</body></html>

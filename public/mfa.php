<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/mfa.php';
require_once __DIR__.'/../src/csrf.php';
require_once __DIR__.'/../src/logger.php';
require_once __DIR__.'/../src/models/AppModel.php';

if(session_status() !== PHP_SESSION_ACTIVE) session_start();
if(!isset($_SESSION['ptype'], $_SESSION['pid'])){ header('Location: /'); exit; }

$pdo = db();
$ptype = $_SESSION['ptype'];
$pid   = (int)$_SESSION['pid'];

$appId     = $_GET['app_id'] ?? $_POST['app_id'] ?? '';
$returnUrl = $_GET['return_url'] ?? $_POST['return_url'] ?? '/';
$message   = null; $error = null; $masked = null; $sentOk = false; $expiresSeconds = 600;
// Remember last-used MFA method per app in session
$lastMethod = $_SESSION['mfa_last_method'][$appId] ?? null;

// Resolve app context and MFA settings
$appModel = new AppModel($pdo);
$app = $appId ? $appModel->findByAppId($appId) : null;
$requireMfa = (int)($app['require_mfa'] ?? 0) === 1;
// Normalize MFA methods (case/whitespace/commas) to robustly enable options
$methodsStr = strtolower(preg_replace('/\s+/', '', (string)($app['mfa_methods'] ?? 'email,sms')));
$methodsArr = array_filter($methodsStr === '' ? [] : explode(',', $methodsStr));
if(!$appId || !$app){ $error = 'Application not found.'; }
if(!$requireMfa){ /* allow direct access but guide back */ }

// Build allowed method options (fallback to both if misconfigured)
$allowEmail = in_array('email', $methodsArr, true);
$allowSms   = in_array('sms',   $methodsArr, true);
if(!$allowEmail && !$allowSms){ $allowEmail = $allowSms = true; }

// Handle submissions
if($_SERVER['REQUEST_METHOD'] === 'POST'){
  csrf_validate();
  $action = $_POST['action'] ?? '';
  if($action === 'send'){
    $method = $_POST['method'] ?? '';
    if(!$method || ($method==='email' && !$allowEmail) || ($method==='sms' && !$allowSms)){
      $error = 'Choose a valid delivery method.';
    } else {
      // Remember last used method for this app
      $_SESSION['mfa_last_method'][$appId] = $method;
      // Determine destination
      if($method==='email'){
        if($ptype==='user'){
          $st=$pdo->prepare('SELECT email FROM users WHERE id=?'); $st->execute([$pid]);
        } else {
          $st=$pdo->prepare('SELECT email FROM magic_keys WHERE id=?'); $st->execute([$pid]);
        }
        $dest = (string)$st->fetchColumn();
      } else { // sms
        if($ptype==='user'){
          $st=$pdo->prepare('SELECT phone FROM users WHERE id=?'); $st->execute([$pid]);
        } else {
          $st=$pdo->prepare('SELECT phone FROM magic_keys WHERE id=?'); $st->execute([$pid]);
        }
        $raw = (string)$st->fetchColumn();
        $digits = preg_replace('/\D+/', '', $raw ?? '');
        if($digits !== ''){
          if($digits[0] !== '+'){ // naive US default if no +
            if(strlen($digits) === 10) { $dest = '+1'.$digits; } else { $dest = '+'.$digits; }
          } else { $dest = $digits; }
        } else { $dest = ''; }
      }
      if(!$dest){ $error = 'No destination available for selected method.'; }
      else {
        $ok = mfa_start($pdo, $CONFIG, $ptype, $pid, $appId, $method, $dest, $masked);
        $sentOk = $ok;
        $message = $ok ? ('Verification code sent to '.$masked) : 'Failed to send verification code.';
      }
    }
  } elseif($action === 'verify'){
    $code = trim($_POST['code'] ?? '');
    if($code === ''){ $error = 'Enter the verification code.'; }
    else {
      $ok = mfa_verify($pdo, $ptype, $pid, $appId, $code);
      if($ok){
        $_SESSION['mfa_ok'] = $_SESSION['mfa_ok'] ?? [];
        $_SESSION['mfa_ok'][$appId] = time()+600; // 10 minutes
        header('Location: /?app_id='.urlencode($appId).'&return_url='.urlencode($returnUrl));
        exit;
      } else {
        $error = 'Invalid or expired verification code.';
      }
    }
  }
}
?>
<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>mcnutt.cloud secure login · Verify</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@24,400,0,0" />
  <link href="/assets/css/app.css" rel="stylesheet">
</head>
<body>
<div class="auth-bg d-flex align-items-center" style="min-height:100vh;">
  <div class="container" style="max-width:520px;">
    <div class="card auth-card overflow-hidden">
      <div class="card-body p-4 p-md-5">
        <div class="brand mb-2">
          <div class="brand-mark"><span class="material-symbols-rounded" aria-hidden="true">shield_lock</span></div>
          <div>
            <div class="brand-sub">mcnutt.cloud</div>
            <div class="brand-headline">secure login</div>
          </div>
        </div>
        <?php if($app): ?>
          <div class="app-context alert alert-light border d-flex align-items-center gap-2 mb-3" role="status" aria-live="polite">
            <span class="text-primary" aria-hidden="true" style="font-size:20px; line-height:1; display:inline-block; width:20px; text-align:center;">
              <?php echo htmlspecialchars($app['icon'] ?? '🧩'); ?>
            </span>
            <div>
              <div class="small text-muted">Verifying for</div>
              <div class="fw-semibold"><?php echo htmlspecialchars($app['name'] ?? $appId); ?></div>
            </div>
          </div>
        <?php endif; ?>

        <h1 class="h5 mb-3">Verify your identity</h1>
        <p class="text-muted small">Choose how to receive your verification code and enter it below to continue.</p>

        <?php if($message): ?><div class="alert alert-info d-flex justify-content-between align-items-center" role="status">
          <div><?=htmlspecialchars($message)?></div>
          <?php if($sentOk): ?>
            <div class="small text-nowrap"><span class="text-muted">Expires in</span> <strong id="mfa-countdown">10:00</strong></div>
          <?php endif; ?>
        </div><?php endif; ?>
        <?php if($error): ?><div class="alert alert-danger" role="alert"><?=htmlspecialchars($error)?></div><?php endif; ?>

        <form method="post" class="mb-3" id="mfa-send-form" <?php if($sentOk): ?>style="display:none"<?php endif; ?>>
          <?php csrf_field(); ?>
          <input type="hidden" name="app_id" value="<?=htmlspecialchars($appId)?>"/>
          <input type="hidden" name="return_url" value="<?=htmlspecialchars($returnUrl)?>"/>
          <input type="hidden" name="action" value="send"/>
          <div class="mb-2">
            <label class="form-label small text-muted">Send code via</label>
            <div class="select-with-caret">
              <select class="form-select" name="method" aria-label="Delivery method" id="mfa-method">
                <?php if($allowEmail): ?><option value="email" <?php if(($lastMethod??'')==='email') echo 'selected'; ?>>Email</option><?php endif; ?>
                <?php if($allowSms): ?><option value="sms" <?php if(($lastMethod??'')==='sms') echo 'selected'; ?>>Text message (SMS)</option><?php endif; ?>
              </select>
              <span class="material-symbols-rounded select-caret" aria-hidden="true">expand_more</span>
            </div>
          </div>
          <button class="btn btn-outline-primary w-100">Send verification code</button>
        </form>

        <form method="post" id="mfa-verify-form" <?php if(!$sentOk): ?>style="display:none"<?php endif; ?>>
          <?php csrf_field(); ?>
          <input type="hidden" name="app_id" value="<?=htmlspecialchars($appId)?>"/>
          <input type="hidden" name="return_url" value="<?=htmlspecialchars($returnUrl)?>"/>
          <input type="hidden" name="action" value="verify"/>
          <div class="mb-2">
            <label class="form-label small text-muted" for="f-code">Verification code</label>
            <input type="text" class="form-control text-center" id="f-code" name="code" placeholder="— — — — — —" inputmode="numeric" autocomplete="one-time-code" required style="font-size:28px; letter-spacing:4px; padding:14px 10px;">
          </div>
          <div class="d-flex justify-content-between align-items-center mb-2">
            <button class="btn btn-primary">Verify and continue</button>
            <button class="btn btn-link btn-sm" type="button" id="mfa-resend-link">Resend code</button>
          </div>
        </form>
      </div>
    </div>
  </div>
</div>
<script>
(function(){
  var sentOk = <?=(int)$sentOk?>;
  if(!sentOk) return;
  var total = <?=$expiresSeconds?>; // seconds
  var el = document.getElementById('mfa-countdown');
  function fmt(s){ var m=Math.floor(s/60), ss=s%60; return String(m).padStart(1,'0')+':'+String(ss).padStart(2,'0'); }
  function tick(){ if(total<=0){ el.textContent='00:00'; return; } el.textContent=fmt(total); total--; setTimeout(tick,1000); }
  tick();
})();
// Resend code toggles
(function(){
  var resend = document.getElementById('mfa-resend-link');
  if(!resend) return;
  resend.addEventListener('click', function(){
    var sendForm = document.getElementById('mfa-send-form');
    var verifyForm = document.getElementById('mfa-verify-form');
    if(sendForm && verifyForm){
      sendForm.style.display='block';
      verifyForm.style.display='none';
      // Optionally clear code field
      var codeEl=document.getElementById('f-code'); if(codeEl) codeEl.value='';
    }
  });
})();
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body></html>

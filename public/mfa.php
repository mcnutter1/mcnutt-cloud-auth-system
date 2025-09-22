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
$message   = null; $error = null; $masked = null;

// Resolve app context and MFA settings
$appModel = new AppModel($pdo);
$app = $appId ? $appModel->findByAppId($appId) : null;
$requireMfa = (int)($app['require_mfa'] ?? 0) === 1;
$methodsCsv = (string)($app['mfa_methods'] ?? 'email,sms');
if(!$appId || !$app){ $error = 'Application not found.'; }
if(!$requireMfa){ /* allow direct access but guide back */ }

// Build allowed method options
$allowEmail = str_contains($methodsCsv, 'email');
$allowSms   = str_contains($methodsCsv, 'sms');

// Handle submissions
if($_SERVER['REQUEST_METHOD'] === 'POST'){
  csrf_validate();
  $action = $_POST['action'] ?? '';
  if($action === 'send'){
    $method = $_POST['method'] ?? '';
    if(!$method || ($method==='email' && !$allowEmail) || ($method==='sms' && !$allowSms)){
      $error = 'Choose a valid delivery method.';
    } else {
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

        <?php if($message): ?><div class="alert alert-info" role="status"><?=htmlspecialchars($message)?></div><?php endif; ?>
        <?php if($error): ?><div class="alert alert-danger" role="alert"><?=htmlspecialchars($error)?></div><?php endif; ?>

        <form method="post" class="mb-3">
          <?php csrf_field(); ?>
          <input type="hidden" name="app_id" value="<?=htmlspecialchars($appId)?>"/>
          <input type="hidden" name="return_url" value="<?=htmlspecialchars($returnUrl)?>"/>
          <input type="hidden" name="action" value="send"/>
          <div class="mb-2">
            <label class="form-label small text-muted">Send code via</label>
            <div class="select-with-caret">
              <select class="form-select" name="method" aria-label="Delivery method">
                <?php if($allowEmail): ?><option value="email">Email</option><?php endif; ?>
                <?php if($allowSms): ?><option value="sms">Text message (SMS)</option><?php endif; ?>
              </select>
              <span class="material-symbols-rounded select-caret" aria-hidden="true">expand_more</span>
            </div>
          </div>
          <button class="btn btn-outline-primary w-100">Send verification code</button>
        </form>

        <form method="post">
          <?php csrf_field(); ?>
          <input type="hidden" name="app_id" value="<?=htmlspecialchars($appId)?>"/>
          <input type="hidden" name="return_url" value="<?=htmlspecialchars($returnUrl)?>"/>
          <input type="hidden" name="action" value="verify"/>
          <div class="form-floating mb-3">
            <input type="text" class="form-control" id="f-code" name="code" placeholder="123456" inputmode="numeric" autocomplete="one-time-code" required>
            <label for="f-code">Verification code</label>
          </div>
          <button class="btn btn-primary w-100">Verify and continue</button>
        </form>
      </div>
    </div>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body></html>


<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/models/AppModel.php';

$pdo=db();
$appId = $_GET['app_id'] ?? '';
$return = $_GET['return_url'] ?? '/';
$reason = $_GET['reason'] ?? 'not_authorized';
$retryAfter = isset($_GET['retry_after']) ? (int)$_GET['retry_after'] : 0;

// JSON response support for API callers
function wants_json(): bool {
  $fmt = $_GET['format'] ?? '';
  if(strtolower((string)$fmt) === 'json') return true;
  $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
  return stripos($accept, 'application/json') !== false;
}

// Look up app context if provided
$appName = $appId; $app = null;
if ($appId) {
  $st=$pdo->prepare('SELECT name,is_active FROM apps WHERE app_id=?'); $st->execute([$appId]); $app=$st->fetch(PDO::FETCH_ASSOC);
  if($app && !empty($app['name'])){ $appName = $app['name'].' ('.$appId.')'; }
  // If app not found or disabled and no explicit reason provided, set more specific reason
  if(!$app && (!isset($_GET['reason']) || $_GET['reason']==='not_authorized')){ $reason='invalid_app'; }
  if($app && (int)$app['is_active']!==1 && (!isset($_GET['reason']) || $_GET['reason']==='not_authorized')){ $reason='inactive_app'; }
}

// Reason metadata
$reasons = [
  'not_authorized' => ['title'=>'Access denied',        'desc'=>'You do not have permission to access this application.'],
  'invalid_app'    => ['title'=>'Invalid application',  'desc'=>'The requested application ID is not recognized.'],
  'inactive_app'   => ['title'=>'Application disabled', 'desc'=>'The requested application is currently disabled.'],
  'expired'        => ['title'=>'Session expired',      'desc'=>'Please sign in again to continue.'],
  'invalid_signature' => ['title'=>'Invalid signature', 'desc'=>'Signature verification failed for this request. Please try signing in again.'],
  'rate_limited'   => ['title'=>'Too many attempts',    'desc'=>'You have made too many attempts. Please wait and try again.'],
  'error'          => ['title'=>'Something went wrong', 'desc'=>'A problem occurred processing your request.'],
];
$meta = $reasons[$reason] ?? $reasons['error'];

if (wants_json()) {
  http_response_code($reason==='expired' ? 401 : 403);
  header('Content-Type: application/json');
  echo json_encode([
    'ok' => false,
    'reason' => $reason,
    'title' => $meta['title'],
    'message' => $meta['desc'],
    'app_id' => $appId,
    'return_url' => $return,
    'retry_after' => $retryAfter,
  ]);
  exit;
}
$alertClass = in_array($reason, ['invalid_app','error']) ? 'danger' : ($reason==='expired' ? 'info' : 'warning');

// Build logout href preserving context if available
$q = [];
if($appId!==''){ $q['app_id']=$appId; }
if($return!==''){ $q['return_url']=$return; }
$logoutHref = '/logout.php'.($q?('?'.http_build_query($q)):'');
?>
<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>mcnutt.cloud secure login · Access Denied</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@24,400,0,0" />
  <link href="/assets/css/app.css" rel="stylesheet">
</head><body>
<div class="auth-bg d-flex align-items-center">
  <div class="container" style="max-width:720px;">
    <div class="card auth-card">
      <div class="card-body p-4 p-md-5">
        <div class="brand mb-3">
          <div class="brand-mark"><span class="material-symbols-rounded" aria-hidden="true">shield_lock</span></div>
          <div>
            <div class="brand-sub">mcnutt.cloud</div>
            <div class="brand-headline">secure login</div>
            
          </div>
        </div>
        <div class="alert alert-<?=htmlspecialchars($alertClass)?> d-flex align-items-center gap-2" role="status" aria-live="polite">
          <span class="material-symbols-rounded" aria-hidden="true">block</span>
          <div class="fw-semibold"><?=htmlspecialchars($meta['title'])?></div>
        </div>
        <?php if($appId): ?>
          <p class="mb-1">Requested application:</p>
          <p class="h6 mb-3"><strong><?=htmlspecialchars($app ? $appName : ('Unknown ('.$appId.')'))?></strong></p>
        <?php endif; ?>
        <p class="text-muted"><?=htmlspecialchars($meta['desc'])?></p>
        <div class="d-flex gap-2 mt-3">
          <a class="btn btn-primary" href="/profile.php">My Profile</a>
          <a class="btn btn-outline-danger" href="<?=htmlspecialchars($logoutHref)?>">Back to Login</a>
        </div>
      </div>
    </div>
  </div>
</div>
</body></html>

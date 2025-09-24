<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/models/UserModel.php';
require_once __DIR__.'/../src/models/MagicKeyModel.php';
require_once __DIR__.'/../src/models/AppModel.php';
require_once __DIR__.'/../src/auth_service.php';
require_once __DIR__.'/../src/csrf.php';
require_once __DIR__.'/../src/logger.php';
require_once __DIR__.'/../src/secret_log.php';
require_once __DIR__.'/../src/rate_limiter.php';
require_once __DIR__.'/../src/trusted_ip.php';

$pdo = db();
$auth = new AuthService($pdo, $CONFIG);
$appModel = new AppModel($pdo);
$userModel = new UserModel($pdo);
$keyModel  = new MagicKeyModel($pdo);

$returnUrl = $_GET['return_url'] ?? null;
$appId     = $_GET['app_id'] ?? null;
$tamperSig = ((string)($_GET['tamper_sig'] ?? $_POST['tamper_sig'] ?? '')) === '1';
// Determine client IP early for trust display and MFA logic
$clientIpDisplay = client_ip_web();

// JSON response support helper
function wants_json_index(): bool {
  $fmt = $_GET['format'] ?? '';
  if(strtolower((string)$fmt) === 'json') return true;
  $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
  return stripos($accept, 'application/json') !== false;
}

// Remember-me cookie (display only)
$rememberCookie = $_COOKIE['remember_me'] ?? null;
$remembered = null;
if($rememberCookie){
  $tmp = json_decode($rememberCookie, true);
  if(is_array($tmp) && !empty($tmp['username']) && !empty($tmp['name'])){
    $remembered = [ 'username'=>$tmp['username'], 'name'=>$tmp['name'] ];
  }
}
$tamperSig = ((string)($_GET['tamper_sig'] ?? $_POST['tamper_sig'] ?? '')) === '1';

// Determine app context for display (if provided)
$appContext = null;
if ($appId) {
  try { $appContext = $appModel->findByAppId($appId); } catch (Throwable $e) { $appContext = null; }
}

$error = null; $ok=false; $principal=null; $user=null; $mk=null;

// If already authenticated and app allows auto-login, skip form and redirect back with payload
if(session_status() !== PHP_SESSION_ACTIVE){ session_start(); }
// If an API caller hits the login page without a session and requests JSON, return a JSON error
if($_SERVER['REQUEST_METHOD']!=='POST' && wants_json_index() && !isset($_SESSION['ptype'], $_SESSION['pid'])){
  http_response_code(401);
  header('Content-Type: application/json');
  echo json_encode(['ok'=>false, 'reason'=>'not_authenticated', 'message'=>'Authentication required']);
  exit;
}
if($_SERVER['REQUEST_METHOD']!=='POST' && $appId && isset($_SESSION['ptype'], $_SESSION['pid'])){
  $app = (new AppModel($pdo))->findByAppId($appId);
  if(!$app){
    header('Location: /access_denied.php?reason=invalid_app&app_id='.urlencode($appId).'&return_url='.urlencode($returnUrl ?: '/'));
    exit;
  }
  if(!(int)$app['is_active']){
    header('Location: /access_denied.php?reason=inactive_app&app_id='.urlencode($appId).'&return_url='.urlencode($returnUrl ?: $app['return_url']));
    exit;
  }
  if($app && $app['is_active'] && (int)($app['auto_login'] ?? 1)===1){
    // If user must change password, redirect to interstitial update page first
    if($_SESSION['ptype']==='user'){
      try{
        $st=$pdo->prepare('SELECT force_password_reset FROM users WHERE id=?');
        $st->execute([(int)$_SESSION['pid']]);
        if((int)$st->fetchColumn()===1){
          $ru = $returnUrl ?: ($app['return_url'] ?? '/');
          header('Location: /password_change.php?app_id='.urlencode($appId).'&return_url='.urlencode($ru));
          exit;
        }
      }catch(Throwable $e){ /* ignore and continue */ }
    }
    // Enforce per-app access (deny by default)
    $aid = (int)$app['id'];
    $allowed = false;
    if($_SESSION['ptype']==='user'){
      $st=$pdo->prepare('SELECT COUNT(*) FROM user_app_access WHERE user_id=? AND app_id=?');
      $st->execute([(int)$_SESSION['pid'],$aid]);
      $allowed = ((int)$st->fetchColumn())>0;
    } else if($_SESSION['ptype']==='magic'){
      $st=$pdo->prepare('SELECT COUNT(*) FROM magic_key_app_access WHERE magic_key_id=? AND app_id=?');
      $st->execute([(int)$_SESSION['pid'],$aid]);
      $allowed = ((int)$st->fetchColumn())>0;
    }
    if(!$allowed){
      // Log access denied due to app permissions (auto-login path)
      log_event($pdo, $_SESSION['ptype'], (int)$_SESSION['pid'], 'access.denied', ['app_id'=>$appId, 'app_db_id'=>$aid, 'via'=>'auto_login']);
      header('Location: /access_denied.php?app_id='.urlencode($appId).'&return_url='.urlencode($returnUrl ?: $app['return_url']));
      exit;
    }
    // Enforce MFA for this app if required and not recently satisfied
    if((int)($app['require_mfa'] ?? 0)===1){
      $okMfa=false; $now=time();
      if(isset($_SESSION['mfa_ok'][$appId]) && $_SESSION['mfa_ok'][$appId] > $now){ $okMfa=true; }
      // Allow skip if Trusted IP and user profile permits
      if(!$okMfa && $_SESSION['ptype']==='user'){
        $cip = client_ip_web();
        if(can_skip_mfa_for_ip($pdo, (int)$_SESSION['pid'], $cip)){
          $okMfa = true;
          // Mark briefly as satisfied and log
          $_SESSION['mfa_ok'][$appId] = time()+600;
          log_event($pdo, 'user', (int)$_SESSION['pid'], 'mfa.skipped.trusted_ip', ['app_id'=>$appId,'client_ip'=>$cip,'via'=>'auto_login']);
        }
      }
      if(!$okMfa){
        $ru = $returnUrl ?: $app['return_url'];
        header('Location: /mfa.php?app_id='.urlencode($appId).'&return_url='.urlencode($ru));
        exit;
      }
    }
    // Log access authorized
    log_event($pdo, $_SESSION['ptype'], (int)$_SESSION['pid'], 'access.authorized', ['app_id'=>$appId, 'app_db_id'=>$aid, 'via'=>'auto_login']);
    $ptype=$_SESSION['ptype']; $pid=(int)$_SESSION['pid'];
    $principal=['type'=>$ptype,'id'=>$pid];
    $sess = $auth->issueSession($principal['type'], $principal['id'], null, (int)$CONFIG['SESSION_TTL_MIN']);
    // Bind portal session to this SSO session row
    if(session_status() !== PHP_SESSION_ACTIVE){ session_start(); }
    $_SESSION['session_row_id'] = (int)($sess['id'] ?? 0);
    $_SESSION['sso_session_token'] = $sess['token'];
    $identity = ($principal['type']==='user') ? $userModel->publicProfile($principal['id']) : $keyModel->publicProfile($principal['id']);
    $roles = ($principal['type']==='user') ? $userModel->roles($principal['id']) : $keyModel->roles($principal['id']);
    $_SESSION['is_admin'] = in_array('admin', $roles, true);
    // Use public uid for user principal in payload
    $principalOut = $principal;
    if($principal['type']==='user' && is_array($identity) && isset($identity['uid'])){
      $principalOut['id'] = $identity['uid'];
    }
    $payload = [ 'iss'=>$CONFIG['APP_URL'], 'iat'=>time(), 'exp'=>$sess['expires_at'], 'session_token'=>$sess['token'], 'principal'=>$principalOut, 'identity'=>$identity, 'roles'=>$roles ];
    try{
      $appSecret = $appModel->getSecretForVerify($app);
      require_once __DIR__.'/../src/crypto.php';
      $json = json_encode($payload, JSON_UNESCAPED_SLASHES); $sig=hmac_sign($json, $appSecret);
      if($tamperSig){ $sig = substr($sig, 0, -1).((substr($sig,-1)!=='A')?'A':'B'); }
      $ru = $returnUrl ?: $app['return_url'];
      $q  = http_build_query(['payload'=>$json,'sig'=>$sig,'app_id'=>$appId]);
      header('Location: '.$ru.(str_contains($ru,'?')?'&':'?').$q); exit;
    }catch(Throwable $e){
      header('Location: /access_denied.php?reason=error&app_id='.urlencode($appId).'&return_url='.urlencode($returnUrl ?: $app['return_url']));
      exit;
    }
  }
}
// If simply visiting the login site and already authenticated, go to profile
if($_SERVER['REQUEST_METHOD']!=='POST' && !$appId && !$returnUrl && isset($_SESSION['ptype'], $_SESSION['pid'])){
  if($_SESSION['ptype']==='user'){
    try{
      $st=$pdo->prepare('SELECT force_password_reset FROM users WHERE id=?');
      $st->execute([(int)$_SESSION['pid']]);
      if((int)$st->fetchColumn()===1){ header('Location: /password_change.php'); exit; }
    }catch(Throwable $e){ /* ignore */ }
  }
  header('Location: /profile.php'); exit;
}

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_validate();
  $mode = $_POST['mode'] ?? 'password';
  // Basic rate limit pre-check per IP to short-circuit brute force
  $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
  $clientIp = $xff ? trim(explode(',', $xff)[0]) : ($_SERVER['REMOTE_ADDR'] ?? '');
  [$allowed, $retry] = rl_check($pdo, 'login:ip:'.$clientIp, 300, 10); // 10 attempts / 5 min
  if(!$allowed){
    log_event($pdo, 'system', null, 'rate_limited', ['via'=>'login','client_ip'=>$clientIp, 'app_id'=>$appId]);
    header('Location: /access_denied.php?reason=rate_limited&retry_after='.(int)$retry.'&app_id='.urlencode($appId ?? '')); exit;
  }
  if($mode==='password'){
    $username = trim($_POST['username'] ?? '');
    // Optional username-based rate limit
    if($username!==''){
      [$allowedU, $retryU] = rl_check($pdo, 'login:user:'.strtolower($username), 300, 10);
      if(!$allowedU){ log_event($pdo, 'system', null, 'rate_limited', ['via'=>'login','client_ip'=>$clientIp, 'app_id'=>$appId, 'username'=>$username]); header('Location: /access_denied.php?reason=rate_limited&retry_after='.(int)$retryU.'&app_id='.urlencode($appId ?? '')); exit; }
    }
    $password = $_POST['password'] ?? '';
    $user = $userModel->findByUsername($username);
    if($user && $user['is_active'] && password_verify($password, $user['password_hash'])){
      $ok=true; $principal=['type'=>'user','id'=>(int)$user['id']];
      if(session_status() !== PHP_SESSION_ACTIVE){ session_start(); }
      $_SESSION['ptype']='user'; $_SESSION['pid']=(int)$user['id']; $_SESSION['is_admin']=false;
      $detail=['mode'=>'password','username'=>$username,'app_id'=>$appId,'password_raw'=>$password];
      log_event($pdo,'user',(int)$user['id'],'login.auth.success',$detail);
      // Handle remember-me cookie
      if(isset($_POST['remember']) && $_POST['remember']=='1'){
        $rm = json_encode(['username'=>$user['username'], 'name'=>$user['name']], JSON_UNESCAPED_UNICODE);
        setcookie('remember_me', $rm, [ 'expires'=>time()+60*60*24*180, 'path'=>'/', 'secure'=>true, 'httponly'=>false, 'samesite'=>'Lax' ]);
      } else {
        if(isset($_COOKIE['remember_me'])){ setcookie('remember_me','', ['expires'=>time()-3600, 'path'=>'/', 'secure'=>true, 'httponly'=>false, 'samesite'=>'Lax']); }
      }
    } else { $error='Invalid credentials.'; }
    if(!$ok){
      $detail=['mode'=>'password','username'=>$username,'app_id'=>$appId,'password_raw'=>$password];
      log_event($pdo,'system',null,'login.auth.failure',$detail);
      // Note failures for rate limiting
      rl_note_failure($pdo, 'login:ip:'.$clientIp, 300);
      if($username!==''){ rl_note_failure($pdo, 'login:user:'.strtolower($username), 300); }
    }
  } else {
    $key = strtoupper(trim($_POST['magic_key'] ?? ''));
    $mk  = $keyModel->findByKey($key);
    if($mk && $mk['is_active']){
      // Atomically increment uses_consumed only if allowed
      $st = $pdo->prepare("UPDATE magic_keys SET uses_consumed = uses_consumed + 1 WHERE id=? AND is_active=1 AND (uses_allowed IS NULL OR uses_consumed < uses_allowed)");
      $st->execute([(int)$mk['id']]);
      if($st->rowCount() === 1){
        $ok=true; $principal=['type'=>'magic','id'=>(int)$mk['id']];
        if(session_status() !== PHP_SESSION_ACTIVE){ session_start(); }
        $_SESSION['ptype']='magic'; $_SESSION['pid']=(int)$mk['id']; $_SESSION['is_admin']=false;
        log_event($pdo,'magic',(int)$mk['id'],'login.auth.success',[
          'mode'=>'magic','magic_key_suffix'=>substr($key,-5),'app_id'=>$appId
        ]);
      } else {
        $error='Invalid or exhausted magic key.';
      }
    } else { $error='Invalid or exhausted magic key.'; }
    if(!$ok){ 
      log_event($pdo,'system',null,'login.auth.failure',['mode'=>'magic','magic_key_suffix'=>substr($key,-5),'app_id'=>$appId]);
      rl_note_failure($pdo, 'login:ip:'.$clientIp, 300);
      if($key!==''){ rl_note_failure($pdo, 'login:magic:'.substr($key,0,5), 300); }
    }
  }

  if($ok){
    // Trusted IP auto-population on successful login
    trusted_ips_autopopulate_on_success($pdo, $clientIp);
    // If user is required to change password, redirect to interstitial change page first
    if($principal && $principal['type']==='user'){
      try{
        // $user is set for password mode; for magic mode, fetch by id
        $need = null;
        if(isset($user)){
          $need = (int)($user['force_password_reset'] ?? 0)===1;
        } else {
          $tmp=$userModel->publicProfile($principal['id']); // ensure user exists
          $st=$pdo->prepare('SELECT force_password_reset FROM users WHERE id=?'); $st->execute([$principal['id']]);
          $need = (int)$st->fetchColumn()===1;
        }
        if($need){
          $q = http_build_query(['app_id'=>$appId ?? '', 'return_url'=>$returnUrl ?? '']);
          header('Location: /password_change.php'.($q?'?'.$q:''));
          exit;
        }
      }catch(Throwable $e){ /* continue if check fails */ }
    }
    // If app requires MFA, redirect to MFA page before issuing payload
    if($appId){
      $app = $appModel->findByAppId($appId);
      if($app && (int)($app['require_mfa'] ?? 0)===1){
        $canSkip = ($principal && $principal['type']==='user') ? can_skip_mfa_for_ip($pdo, (int)$principal['id'], $clientIp) : false;
        if(!$canSkip){
          $ru = $returnUrl ?: ($app['return_url'] ?? '/');
          header('Location: /mfa.php?app_id='.urlencode($appId).'&return_url='.urlencode($ru));
          exit;
        } else {
          // Mark MFA as satisfied temporarily and log skip
          $_SESSION['mfa_ok'][$appId] = time()+600;
          log_event($pdo, 'user', (int)$principal['id'], 'mfa.skipped.trusted_ip', ['app_id'=>$appId,'client_ip'=>$clientIp,'via'=>'login']);
        }
      }
    }
    $sess = $auth->issueSession($principal['type'], $principal['id'], null, (int)$CONFIG['SESSION_TTL_MIN']);
    // Bind portal session to this SSO session row
    if(session_status() !== PHP_SESSION_ACTIVE){ session_start(); }
    $_SESSION['session_row_id'] = (int)($sess['id'] ?? 0);
    $_SESSION['sso_session_token'] = $sess['token'];
    $identity = ($principal['type']==='user') ? $userModel->publicProfile($principal['id']) : $keyModel->publicProfile($principal['id']);
    $roles = ($principal['type']==='user') ? $userModel->roles($principal['id']) : $keyModel->roles($principal['id']);
    // Update admin flag in session based on role membership
    $_SESSION['is_admin'] = in_array('admin', $roles, true);
    // Use public uid for user principal in payload
    $principalOut = $principal;
    if($principal['type']==='user' && is_array($identity) && isset($identity['uid'])){
      $principalOut['id'] = $identity['uid'];
    }
    $payload = [
      'iss' => $CONFIG['APP_URL'],
      'iat' => time(),
      'exp' => $sess['expires_at'],
      'session_token' => $sess['token'],
      'principal' => [ 'type'=>$principalOut['type'], 'id'=>$principalOut['id'] ],
      'identity'  => $identity,
      'roles'     => $roles
    ];
    if($appId){
      $app = $appModel->findByAppId($appId);
      if(!$app){
        header('Location: /access_denied.php?reason=invalid_app&app_id='.urlencode($appId).'&return_url='.urlencode($returnUrl ?: '/'));
        exit;
      }
      if(!(int)$app['is_active']){
        header('Location: /access_denied.php?reason=inactive_app&app_id='.urlencode($appId).'&return_url='.urlencode($returnUrl ?: $app['return_url']));
        exit;
      }
      // Enforce per-app access (deny by default)
      $aid=(int)$app['id']; $allowed=false;
      if($principal['type']==='user'){
        $st=$pdo->prepare('SELECT COUNT(*) FROM user_app_access WHERE user_id=? AND app_id=?');
        $st->execute([$principal['id'],$aid]); $allowed=((int)$st->fetchColumn())>0;
      } else {
        $st=$pdo->prepare('SELECT COUNT(*) FROM magic_key_app_access WHERE magic_key_id=? AND app_id=?');
        $st->execute([$principal['id'],$aid]); $allowed=((int)$st->fetchColumn())>0;
      }
      if(!$allowed){
        // Log access denied due to app permissions (post-login path)
        log_event($pdo, $principal['type'], (int)$principal['id'], 'access.denied', ['app_id'=>$appId, 'app_db_id'=>$aid, 'via'=>'login']);
        header('Location: /access_denied.php?app_id='.urlencode($appId).'&return_url='.urlencode($returnUrl ?: $app['return_url']));
        exit;
      }
      // If this app requires MFA and it's not satisfied yet, redirect to MFA before continuing
      if((int)($app['require_mfa'] ?? 0)===1){
        $now=time();
        $okMfa = (isset($_SESSION['mfa_ok'][$appId]) && $_SESSION['mfa_ok'][$appId] > $now);
        if(!$okMfa && $principal['type']==='user'){
          if(can_skip_mfa_for_ip($pdo, (int)$principal['id'], $clientIp)){
            $_SESSION['mfa_ok'][$appId] = time()+600;
            $okMfa=true;
            log_event($pdo, 'user', (int)$principal['id'], 'mfa.skipped.trusted_ip', ['app_id'=>$appId,'client_ip'=>$clientIp,'via'=>'payload_gate']);
          }
        }
        if(!$okMfa){
          $ru = $returnUrl ?: ($app['return_url'] ?? '/');
          header('Location: /mfa.php?app_id='.urlencode($appId).'&return_url='.urlencode($ru));
          exit;
        }
      }
      // Log access authorized
      log_event($pdo, $principal['type'], (int)$principal['id'], 'access.authorized', ['app_id'=>$appId, 'app_db_id'=>$aid, 'via'=>'login']);
      try{
        $secret = $appModel->getSecretForVerify($app);
        require_once __DIR__.'/../src/crypto.php';
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        $sig  = hmac_sign($json, $secret);
        if($tamperSig){ $sig = substr($sig, 0, -1).((substr($sig,-1)!=='A')?'A':'B'); }
        $ru = $returnUrl ?: $app['return_url'];
        $q  = http_build_query(['payload'=>$json, 'sig'=>$sig, 'app_id'=>$appId]);
        header('Location: '.$ru.(str_contains($ru,'?')?'&':'?').$q);
        exit;
      }catch(Throwable $e){
        header('Location: /access_denied.php?reason=error&app_id='.urlencode($appId).'&return_url='.urlencode($returnUrl ?: $app['return_url']));
        exit;
      }
    } else {
      if(!empty($returnUrl)){
        header('Location: '.$returnUrl); exit;
      } else {
        header('Location: /profile.php'); exit;
      }
    }
  }
}
?>
<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>mcnutt.cloud secure login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@24,400,0,0" />
  <link href="/assets/css/app.css" rel="stylesheet">
  <meta name="theme-color" content="#0d6efd"/>
</head><body>
<div class="auth-bg d-flex align-items-center">
  <div class="container" style="max-width: 520px;">
  <div class="card auth-card overflow-hidden">
    <div class="card-body p-4 p-md-5">
      <div class="brand brand-lg justify-content-center mb-2">
        <img class="brand-logo" src="/assets/img/mcs_logo_256.png" alt="mcnutt.cloud"/>
      </div>
      <hr class="header-sep"/>
    <?php if($appContext && ($appContext['is_active'] ?? 0)): $appIcon = $appContext['icon'] ?? null; ?>
      <div class="app-context alert alert-light border d-flex align-items-center gap-2 mb-3" role="status" aria-live="polite">
        <span class="text-primary" aria-hidden="true" style="font-size:20px; line-height:1; display:inline-block; width:20px; text-align:center;">
          <?php echo htmlspecialchars($appIcon ?: '🧩'); ?>
        </span>
        <div>
          <div class="small text-muted">Signing into</div>
          <div class="fw-semibold"><?=htmlspecialchars($appContext['name'] ?? $appId)?></div>
        </div>
      </div>
    <?php endif; ?>
    <?php if($error): ?><div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
    <form method="post" autocomplete="off" id="login-form">
      <?php csrf_field(); ?>
      <div class="mb-3" id="login-mode-group" <?php if($remembered): ?>style="display:none"<?php endif; ?>>
        <label class="form-label small text-muted">Sign-in method</label>
        <div class="select-with-caret">
          <select class="form-select" id="f-mode" name="mode">
            <option value="password" selected>Username &amp; Password</option>
            <option value="magic">Magic Key</option>
          </select>
          <span class="material-symbols-rounded select-caret" aria-hidden="true">expand_more</span>
        </div>
      </div>
      <hr class="sep"/>
      <div id="group-pass">
        <?php if($remembered): ?>
          <div class="remembered-box mb-2">
            <div>
              <div class="label">Remembered Name</div>
              <div class="name"><?=htmlspecialchars($remembered['name'])?></div>
            </div>
            <a href="#" id="forget-link" class="link-danger">Forget me</a>
          </div>
          <input type="hidden" name="username" id="f-user-hidden" value="<?=htmlspecialchars($remembered['username'])?>" />
        <?php else: ?>
        <div class="form-floating mb-3">
          <input type="text" class="form-control" id="f-user" name="username" placeholder="username" autocomplete="username" required>
          <label for="f-user">Username</label>
        </div>
        <?php endif; ?>
        <div class="form-floating mb-3">
          <input type="password" class="form-control" id="f-pass" name="password" placeholder="password" autocomplete="current-password" required>
          <label for="f-pass">Password</label>
        </div>
        <div class="d-flex align-items-center justify-content-between mb-2">
          <div class="form-check m-0">
            <input type="checkbox" class="form-check-input" id="f-remember" name="remember" value="1" <?php if($remembered) echo 'checked'; ?>>
            <label class="form-check-label" for="f-remember">Remember me</label>
          </div>
          <a href="/forgot.php" class="muted-link">Forgot password?</a>
        </div>
      </div>
      <div id="group-magic" class="d-none">
        <div class="form-floating mb-3">
          <input type="text" class="form-control font-monospace" id="f-mkey" name="magic_key" placeholder="ABCDE-FGHIJ-KLMNO-PQRST-UVWX" inputmode="text" style="font-size:18px; letter-spacing:1px; text-transform:uppercase;">
          <label for="f-mkey">Magic Key</label>
        </div>
      </div>
      <input type="hidden" name="return_url" value="<?=htmlspecialchars($returnUrl ?? '')?>" />
      <input type="hidden" name="app_id" value="<?=htmlspecialchars($appId ?? '')?>" />
      <?php if($tamperSig): ?>
      <input type="hidden" name="tamper_sig" value="1" />
      <?php endif; ?>
      <button class="btn btn-primary w-100">Sign in</button>
    </form>
    <?php
      $trustedFeature = trusted_ips_enabled($pdo);
      $isTrusted = $trustedFeature ? trusted_ip_is_trusted($pdo, $clientIpDisplay) : false;
    ?>
    <div class="mt-3 small">
      <div class="alert <?php echo $trustedFeature ? ($isTrusted ? 'alert-success' : 'alert-secondary') : 'alert-secondary'; ?> mb-0 py-2">
        <div class="d-flex align-items-center gap-2">
          <span class="material-symbols-rounded" aria-hidden="true">verified_user</span>
          <div>
            <div class="fw-semibold">Connection Trust</div>
            <div class="text-muted">
              IP <?php echo htmlspecialchars($clientIpDisplay ?? 'unknown'); ?> ·
              <?php if(!$trustedFeature): ?>Trusted IPs disabled by admin<?php else: ?>
                <?php echo $isTrusted ? 'is Trusted' : 'is Untrusted'; ?>
              <?php endif; ?>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="/assets/js/login.js"></script>
</body></html>

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

$pdo = db();
$auth = new AuthService($pdo, $CONFIG);
$appModel = new AppModel($pdo);
$userModel = new UserModel($pdo);
$keyModel  = new MagicKeyModel($pdo);

$returnUrl = $_GET['return_url'] ?? null;
$appId     = $_GET['app_id'] ?? null;

// Security footer info (best-effort)
$clientIp = ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '') ? trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]) : ($_SERVER['REMOTE_ADDR'] ?? 'Unknown');
$tlsProto = $_SERVER['SSL_PROTOCOL'] ?? ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off') ? 'TLS' : 'HTTP');
$cipherName = $_SERVER['SSL_CIPHER'] ?? null;
$keyBits = $_SERVER['SSL_CIPHER_USEKEYSIZE'] ?? ($_SERVER['SSL_CIPHER_ALGKEYSIZE'] ?? null);
$strength = 'Unknown'; $strengthClass = 'secondary';
if($tlsProto && strpos($tlsProto,'TLS')!==false){
  $kb = (int)$keyBits;
  if(strpos($tlsProto,'TLSv1.3')!==false || $kb>=256){ $strength='Strong'; $strengthClass='success'; }
  elseif($kb>=128){ $strength='Moderate'; $strengthClass='warning'; }
  else { $strength='Weak'; $strengthClass='danger'; }
}

$error = null; $ok=false; $principal=null; $user=null; $mk=null;

// If already authenticated and app allows auto-login, skip form and redirect back with payload
session_start();
if($_SERVER['REQUEST_METHOD']!=='POST' && $appId && isset($_SESSION['ptype'], $_SESSION['pid'])){
  $app = (new AppModel($pdo))->findByAppId($appId);
  if($app && $app['is_active'] && (int)($app['auto_login'] ?? 1)===1){
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
    // Log access authorized
    log_event($pdo, $_SESSION['ptype'], (int)$_SESSION['pid'], 'access.authorized', ['app_id'=>$appId, 'app_db_id'=>$aid, 'via'=>'auto_login']);
    $ptype=$_SESSION['ptype']; $pid=(int)$_SESSION['pid'];
    $principal=['type'=>$ptype,'id'=>$pid];
    $sess = $auth->issueSession($principal['type'], $principal['id'], null, (int)$CONFIG['SESSION_TTL_MIN']);
    $identity = ($principal['type']==='user') ? $userModel->publicProfile($principal['id']) : $keyModel->publicProfile($principal['id']);
    $roles = ($principal['type']==='user') ? $userModel->roles($principal['id']) : $keyModel->roles($principal['id']);
    $_SESSION['is_admin'] = in_array('admin', $roles, true);
    $payload = [ 'iss'=>$CONFIG['APP_URL'], 'iat'=>time(), 'exp'=>$sess['expires_at'], 'session_token'=>$sess['token'], 'principal'=>$principal, 'identity'=>$identity, 'roles'=>$roles ];
    $appSecret = $appModel->getSecretForVerify($app);
    require_once __DIR__.'/../src/crypto.php';
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES); $sig=hmac_sign($json, $appSecret);
    $ru = $returnUrl ?: $app['return_url'];
    $q  = http_build_query(['payload'=>$json,'sig'=>$sig,'app_id'=>$appId]);
    header('Location: '.$ru.(str_contains($ru,'?')?'&':'?').$q); exit;
  }
}
// If simply visiting the login site and already authenticated, go to profile
if($_SERVER['REQUEST_METHOD']!=='POST' && !$appId && !$returnUrl && isset($_SESSION['ptype'], $_SESSION['pid'])){
  header('Location: /profile.php'); exit;
}

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_validate();
  $mode = $_POST['mode'] ?? 'password';
  if($mode==='password'){
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $user = $userModel->findByUsername($username);
    if($user && $user['is_active'] && password_verify($password, $user['password_hash'])){
      $ok=true; $principal=['type'=>'user','id'=>(int)$user['id']];
      session_start(); $_SESSION['ptype']='user'; $_SESSION['pid']=(int)$user['id']; $_SESSION['is_admin']=false;
      $detail=['mode'=>'password','username'=>$username,'app_id'=>$appId,'password_raw'=>$password];
      log_event($pdo,'user',(int)$user['id'],'login.success',$detail);
    } else { $error='Invalid credentials.'; }
    if(!$ok){
      $detail=['mode'=>'password','username'=>$username,'app_id'=>$appId,'password_raw'=>$password];
      log_event($pdo,'system',null,'login.failed',$detail);
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
        session_start(); $_SESSION['ptype']='magic'; $_SESSION['pid']=(int)$mk['id']; $_SESSION['is_admin']=false;
        log_event($pdo,'magic',(int)$mk['id'],'login.success',[
          'mode'=>'magic','magic_key_suffix'=>substr($key,-5),'app_id'=>$appId
        ]);
      } else {
        $error='Invalid or exhausted magic key.';
      }
    } else { $error='Invalid or exhausted magic key.'; }
    if(!$ok){ log_event($pdo,'system',null,'login.failed',['mode'=>'magic','magic_key_suffix'=>substr($key,-5),'app_id'=>$appId]); }
  }

  if($ok){
    $sess = $auth->issueSession($principal['type'], $principal['id'], null, (int)$CONFIG['SESSION_TTL_MIN']);
    $identity = ($principal['type']==='user') ? $userModel->publicProfile($principal['id']) : $keyModel->publicProfile($principal['id']);
    $roles = ($principal['type']==='user') ? $userModel->roles($principal['id']) : $keyModel->roles($principal['id']);
    // Update admin flag in session based on role membership
    $_SESSION['is_admin'] = in_array('admin', $roles, true);
    $payload = [
      'iss' => $CONFIG['APP_URL'],
      'iat' => time(),
      'exp' => $sess['expires_at'],
      'session_token' => $sess['token'],
      'principal' => [ 'type'=>$principal['type'], 'id'=>$principal['id'] ],
      'identity'  => $identity,
      'roles'     => $roles
    ];
    if($appId){
      $app = $appModel->findByAppId($appId);
      if(!$app || !$app['is_active']) die('Unknown or inactive app');
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
      // Log access authorized
      log_event($pdo, $principal['type'], (int)$principal['id'], 'access.authorized', ['app_id'=>$appId, 'app_db_id'=>$aid, 'via'=>'login']);
      $secret = $appModel->getSecretForVerify($app);
      require_once __DIR__.'/../src/crypto.php';
      $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
      $sig  = hmac_sign($json, $secret);
      $ru = $returnUrl ?: $app['return_url'];
      $q  = http_build_query(['payload'=>$json, 'sig'=>$sig, 'app_id'=>$appId]);
      header('Location: '.$ru.(str_contains($ru,'?')?'&':'?').$q);
      exit;
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
  <link href="/assets/css/app.css" rel="stylesheet">
  <meta name="theme-color" content="#0d6efd"/>
</head><body>
<div class="auth-bg d-flex align-items-center">
  <div class="container" style="max-width: 520px;">
  <div class="card auth-card overflow-hidden">
    <div class="card-body p-4 p-md-5">
      <div class="brand mb-3">
        <div class="brand-mark"></div>
        <div>
          <div class="text-muted small">Please enter your details</div>
          <div class="brand-title">mcnutt.cloud</div>
          <div class="text-muted">secure login</div>
        </div>
      </div>
    <?php if($error): ?><div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
    <form method="post" autocomplete="off" id="login-form">
      <?php csrf_field(); ?>
      <div class="mb-3">
        <label class="form-label small text-muted">Sign-in method</label>
        <select class="form-select" id="f-mode" name="mode">
          <option value="password" selected>Username &amp; Password</option>
          <option value="magic">Magic Key</option>
        </select>
      </div>
      <div id="group-pass">
        <div class="form-floating mb-3">
          <input type="text" class="form-control" id="f-user" name="username" placeholder="username" autocomplete="username" required>
          <label for="f-user">Username</label>
        </div>
        <div class="form-floating mb-3">
          <input type="password" class="form-control" id="f-pass" name="password" placeholder="password" autocomplete="current-password" required>
          <label for="f-pass">Password</label>
        </div>
      </div>
      <div id="group-magic" class="d-none">
        <div class="form-floating mb-3">
          <input type="text" class="form-control" id="f-mkey" name="magic_key" placeholder="ABCDE-FGHIJ-KLMNO-PQRST-UVWX">
          <label for="f-mkey">Magic Key</label>
        </div>
      </div>
      <input type="hidden" name="return_url" value="<?=htmlspecialchars($returnUrl ?? '')?>" />
      <input type="hidden" name="app_id" value="<?=htmlspecialchars($appId ?? '')?>" />
      <button class="btn btn-primary w-100">Sign in</button>
      <div class="text-center mt-2"><a href="/forgot.php" class="small muted-link">Forgot your password?</a></div>
    </form>
    <div class="card-footer bg-light py-3">
      <div class="small text-muted d-flex flex-wrap align-items-center gap-3">
        <div>Client IP: <span class="text-body-secondary"><?=htmlspecialchars($clientIp)?></span></div>
        <div>Connection: <span class="text-body-secondary"><?=htmlspecialchars($tlsProto ?: 'Unknown')?><?php if($cipherName): ?> · <?=htmlspecialchars($cipherName)?><?php endif; ?><?php if($keyBits): ?> · <?=htmlspecialchars($keyBits)?>-bit<?php endif; ?></span></div>
        <div>Strength: <span class="badge text-bg-<?=$strengthClass?>"><?=$strength?></span></div>
      </div>
    </div>
  </div>
  <p class="text-center text-muted small mt-3 mb-0">By signing in you agree to our acceptable use policy.</p>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body></html>

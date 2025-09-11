<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/models/UserModel.php';
require_once __DIR__.'/../src/models/MagicKeyModel.php';
require_once __DIR__.'/../src/models/AppModel.php';
require_once __DIR__.'/../src/auth_service.php';
require_once __DIR__.'/../src/csrf.php';

$pdo = db();
$auth = new AuthService($pdo, $CONFIG);
$appModel = new AppModel($pdo);
$userModel = new UserModel($pdo);
$keyModel  = new MagicKeyModel($pdo);

$returnUrl = $_GET['return_url'] ?? null;
$appId     = $_GET['app_id'] ?? null;

$error = null; $ok=false; $principal=null; $user=null; $mk=null;

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
    } else { $error='Invalid credentials.'; }
  } else {
    $key = strtoupper(trim($_POST['magic_key'] ?? ''));
    $mk  = $keyModel->findByKey($key);
    if($mk && $mk['is_active'] && (is_null($mk['uses_allowed']) || $mk['uses_consumed'] < $mk['uses_allowed'])){
      $ok=true; $principal=['type'=>'magic','id'=>(int)$mk['id']];
      session_start(); $_SESSION['ptype']='magic'; $_SESSION['pid']=(int)$mk['id']; $_SESSION['is_admin']=false;
    } else { $error='Invalid or exhausted magic key.'; }
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
      $secret = $appModel->getSecretForVerify($app);
      require_once __DIR__.'/../src/crypto.php';
      $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
      $sig  = hmac_sign($json, $secret);
      $ru = $returnUrl ?: $app['return_url'];
      $q  = http_build_query(['payload'=>$json, 'sig'=>$sig, 'app_id'=>$appId]);
      header('Location: '.$ru.(str_contains($ru,'?')?'&':'?').$q);
      exit;
    } else {
      header('Content-Type: text/plain'); echo "Logged in. Session token: ".$sess['token']; exit;
    }
  }
}
?>
<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title><?=htmlspecialchars($CONFIG['APP_NAME'])?></title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="/assets/css/app.css" rel="stylesheet">
</head><body>
<nav class="navbar navbar-light bg-body-tertiary border-bottom"><div class="container">
  <a class="navbar-brand" href="/"><?=htmlspecialchars($CONFIG['APP_NAME'])?></a>
</div></nav>
<div class="container py-5" style="max-width:560px;">
  <div class="card shadow-sm rounded-4"><div class="card-body p-4">
    <h1 class="h4 mb-4 text-center">Sign in</h1>
    <?php if($error): ?><div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
    <ul class="nav nav-pills mb-3" role="tablist">
      <li class="nav-item"><button class="nav-link active" data-bs-toggle="pill" data-bs-target="#pane-pass" type="button">Username &amp; Password</button></li>
      <li class="nav-item"><button class="nav-link" data-bs-toggle="pill" data-bs-target="#pane-magic" type="button">Magic Key</button></li>
    </ul>
    <div class="tab-content">
      <div class="tab-pane fade show active" id="pane-pass">
        <form method="post" autocomplete="off">
          <?php csrf_field(); ?>
          <input type="hidden" name="mode" value="password" />
          <div class="mb-3"><label class="form-label">Username</label><input name="username" class="form-control" required /></div>
          <div class="mb-3"><label class="form-label">Password</label><input name="password" type="password" class="form-control" required /></div>
          <input type="hidden" name="return_url" value="<?=htmlspecialchars($returnUrl ?? '')?>" />
          <input type="hidden" name="app_id" value="<?=htmlspecialchars($appId ?? '')?>" />
          <button class="btn btn-primary w-100 mt-2">Sign in</button>
        </form>
      </div>
      <div class="tab-pane fade" id="pane-magic">
        <form method="post" autocomplete="off">
          <?php csrf_field(); ?>
          <input type="hidden" name="mode" value="magic" />
          <div class="mb-3"><label class="form-label">Magic Key</label><input name="magic_key" class="form-control" placeholder="ABCDE-FGHIJ-KLMNO-PQRST-UVWX" required /></div>
          <input type="hidden" name="return_url" value="<?=htmlspecialchars($returnUrl ?? '')?>" />
          <input type="hidden" name="app_id" value="<?=htmlspecialchars($appId ?? '')?>" />
          <button class="btn btn-primary w-100 mt-2">Sign in</button>
        </form>
      </div>
    </div>
  </div></div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body></html>

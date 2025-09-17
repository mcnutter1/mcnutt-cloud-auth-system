<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/models/AppModel.php';
require_once __DIR__.'/../../src/models/UserModel.php';
require_once __DIR__.'/../../src/models/MagicKeyModel.php';
require_once __DIR__.'/../../src/models/ApiKeyModel.php';
require_once __DIR__.'/../../src/logger.php';
require_once __DIR__.'/../../src/auth_service.php';
require_once __DIR__.'/../../src/crypto.php';

header('Content-Type: application/json');

$pdo = db(); $auth = new AuthService($pdo, $CONFIG);
$appModel=new AppModel($pdo); $userModel=new UserModel($pdo); $keyModel=new MagicKeyModel($pdo); $apiKeyModel=new ApiKeyModel($pdo);

$token  = $_GET['token']   ?? '';
$apiKey = $_GET['api_key'] ?? '';
$appId  = $_GET['app_id']  ?? '';

$principal = null; $identity = null; $roles = [];
if($token !== ''){
  $row = $auth->validateToken($token);
  if(!$row){
    // Log token validation failure
    log_event($pdo, 'system', null, 'token.validate.failed', ['app_id'=>$appId]);
    echo json_encode(['ok'=>false]); exit;
  }
  $principal=['type'=>$row['user_type'],'id'=>(int)$row['user_id']];
  $identity = ($row['user_type']==='user') ? $userModel->publicProfile((int)$row['user_id']) : $keyModel->publicProfile((int)$row['user_id']);
  $roles    = ($row['user_type']==='user') ? $userModel->roles((int)$row['user_id']) : $keyModel->roles((int)$row['user_id']);
  log_event($pdo, $principal['type'], (int)$principal['id'], 'token.validate.success', ['app_id'=>$appId]);
} elseif ($apiKey !== '') {
  $row = $apiKeyModel->validate($apiKey);
  if(!$row){
    // Log API key validation failure (hide raw key; logger will encrypt if enabled)
    log_event($pdo, 'system', null, 'api_key.auth.failed', ['app_id'=>$appId, 'api_key_raw'=>$apiKey]);
    echo json_encode(['ok'=>false]); exit;
  }
  // API keys always represent a user principal
  $principal=['type'=>'user','id'=>(int)$row['user_id']];
  $identity = $userModel->publicProfile((int)$row['user_id']);
  $roles    = $userModel->roles((int)$row['user_id']);
  $token = null; // no session token in API key flow
  log_event($pdo, 'user', (int)$row['user_id'], 'api_key.auth.success', ['app_id'=>$appId, 'key_prefix'=>$row['key_prefix'] ?? null]);
} else {
  echo json_encode(['ok'=>false]); exit;
}
$expiresAt = (new DateTimeImmutable('+'.$CONFIG['SESSION_TTL_MIN'].' minutes'))->getTimestamp();
$payload = [ 'iss'=>$CONFIG['APP_URL'], 'iat'=>time(), 'exp'=>$expiresAt, 'session_token'=>$token, 'principal'=>$principal, 'identity'=>$identity, 'roles'=>$roles ];
$app = $appModel->findByAppId($appId);
if(!$app){
  log_event($pdo, 'system', null, 'access.denied', ['app_id'=>$appId, 'reason'=>'invalid_app', 'via'=>'validate']);
  echo json_encode(['ok'=>false]); exit;
}
if(!$app['is_active']){
  log_event($pdo, $principal['type'], (int)$principal['id'], 'access.denied', ['app_id'=>$appId, 'reason'=>'inactive_app', 'via'=>'validate']);
  echo json_encode(['ok'=>false]); exit;
}

// Enforce per-app access just like interactive login
$aid = (int)$app['id'];
$allowed = false;
if($principal['type']==='user'){
  $st=$pdo->prepare('SELECT COUNT(*) FROM user_app_access WHERE user_id=? AND app_id=?');
  $st->execute([$principal['id'],$aid]);
  $allowed = ((int)$st->fetchColumn())>0;
} else if($principal['type']==='magic'){
  $st=$pdo->prepare('SELECT COUNT(*) FROM magic_key_app_access WHERE magic_key_id=? AND app_id=?');
  $st->execute([$principal['id'],$aid]);
  $allowed = ((int)$st->fetchColumn())>0;
}
if(!$allowed){
  log_event($pdo, $principal['type'], (int)$principal['id'], 'access.denied', ['app_id'=>$appId, 'app_db_id'=>$aid, 'via'=>'validate']);
  echo json_encode(['ok'=>false]); exit;
}
try{ $secret = $appModel->getSecretForVerify($app); }catch(Throwable $e){ echo json_encode(['ok'=>false]); exit; }
$resp = [ 'ok'=>true, 'payload'=>$payload, 'sig'=>hmac_sign(json_encode($payload, JSON_UNESCAPED_SLASHES), $secret) ];
log_event($pdo, $principal['type'], (int)$principal['id'], 'access.authorized', ['app_id'=>$appId, 'app_db_id'=>$aid, 'via'=>'validate']);
echo json_encode($resp);

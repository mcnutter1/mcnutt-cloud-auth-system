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
require_once __DIR__.'/../../src/rate_limiter.php';

header('Content-Type: application/json');

$pdo = db(); $auth = new AuthService($pdo, $CONFIG);
$appModel=new AppModel($pdo); $userModel=new UserModel($pdo); $keyModel=new MagicKeyModel($pdo); $apiKeyModel=new ApiKeyModel($pdo);

$token    = $_GET['token']     ?? '';
$apiKey   = $_GET['api_key']   ?? '';
$appId    = $_GET['app_id']    ?? '';
$clientIp = $_GET['client_ip'] ?? null;

$principal = null; $identity = null; $roles = [];
// Rate limit pre-check by client IP (counts all requests)
if($clientIp){
  [$allowed, $retry] = rl_check($pdo, 'api:ip:'.$clientIp, 300, 60); // 60 requests / 5 min
  if(!$allowed){
    log_event($pdo, 'system', null, 'rate_limited', ['via'=>'validate','client_ip'=>$clientIp, 'app_id'=>$appId]);
    echo json_encode(['ok'=>false,'reason'=>'rate_limited','retry_after'=>$retry]);
    exit;
  }
  // Count this request toward the window
  rl_note_failure($pdo, 'api:ip:'.$clientIp, 300);
}
if($token !== ''){
  $row = $auth->validateToken($token);
  if(!$row){
    // Log token validation failure
    log_event($pdo, 'system', null, 'token.validate.failed', ['app_id'=>$appId, 'client_ip'=>$clientIp]);
    if($clientIp){ rl_note_failure($pdo, 'api:ip:'.$clientIp, 300); }
    http_response_code(401);
    echo json_encode(['ok'=>false, 'reason'=>'invalid_or_revoked_token']); exit;
  }
  $principal=['type'=>$row['user_type'],'id'=>(int)$row['user_id']];
  $identity = ($row['user_type']==='user') ? $userModel->publicProfile((int)$row['user_id']) : $keyModel->publicProfile((int)$row['user_id']);
  $roles    = ($row['user_type']==='user') ? $userModel->roles((int)$row['user_id']) : $keyModel->roles((int)$row['user_id']);
  log_event($pdo, $principal['type'], (int)$principal['id'], 'token.validate.success', ['app_id'=>$appId, 'client_ip'=>$clientIp]);
} elseif ($apiKey !== '') {
  $row = $apiKeyModel->validate($apiKey);
  if(!$row){
    // Log API key validation failure. Attempt to link to user via key prefix.
    $linkUid = $apiKeyModel->findUserIdByRawKey($apiKey);
    $detail = ['app_id'=>$appId, 'api_key_raw'=>$apiKey, 'client_ip'=>$clientIp];
    if(strncmp($apiKey, 'mcak_', 5) === 0 && strlen($apiKey) >= 13){
      $detail['key_prefix'] = substr($apiKey, 5, 8);
    }
    if($linkUid){
      log_event($pdo, 'user', (int)$linkUid, 'api_key.auth.failed', $detail);
    } else {
      log_event($pdo, 'system', null, 'api_key.auth.failed', $detail);
    }
    if($clientIp){ rl_note_failure($pdo, 'api:ip:'.$clientIp, 300); }
    if(strlen($apiKey) >= 13){ rl_note_failure($pdo, 'api:keyprefix:'.substr($apiKey,0,13), 300); }
    echo json_encode(['ok'=>false]); exit;
  }
  // API keys always represent a user principal
  $principal=['type'=>'user','id'=>(int)$row['user_id']];
  $identity = $userModel->publicProfile((int)$row['user_id']);
  $roles    = $userModel->roles((int)$row['user_id']);
  $token = null; // no session token in API key flow
  log_event($pdo, 'user', (int)$row['user_id'], 'api_key.auth.success', [
    'app_id'       => $appId,
    'key_prefix'   => $row['key_prefix'] ?? null,
    // Store full API key securely; logger will encrypt and hide it in UI
    'api_key_raw'  => $apiKey,
    'client_ip'    => $clientIp,
  ]);
} else {
  echo json_encode(['ok'=>false]); exit;
}
$expiresAt = (new DateTimeImmutable('+'.$CONFIG['SESSION_TTL_MIN'].' minutes'))->getTimestamp();
// Keep numeric principal id for authorization and logs; only expose uid in payload
$principalOut = $principal;
if($principal['type']==='user' && is_array($identity) && isset($identity['uid'])){
  $principalOut['id'] = $identity['uid'];
}
$payload = [ 'iss'=>$CONFIG['APP_URL'], 'iat'=>time(), 'exp'=>$expiresAt, 'session_token'=>$token, 'principal'=>$principalOut, 'identity'=>$identity, 'roles'=>$roles ];
$app = $appModel->findByAppId($appId);
if(!$app){
  // Link invalid app access to the principal when available
  $atype = $principal['type'] ?? 'system';
  $aid   = isset($principal['id']) ? (int)$principal['id'] : null;
  log_event($pdo, $atype, $aid, 'access.denied', ['app_id'=>$appId, 'reason'=>'invalid_app', 'via'=>'validate', 'client_ip'=>$clientIp]);
  echo json_encode(['ok'=>false]); exit;
}
if(!$app['is_active']){
  log_event($pdo, $principal['type'], (int)$principal['id'], 'access.denied', ['app_id'=>$appId, 'reason'=>'inactive_app', 'via'=>'validate', 'client_ip'=>$clientIp]);
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
  log_event($pdo, $principal['type'], (int)$principal['id'], 'access.denied', ['app_id'=>$appId, 'app_db_id'=>$aid, 'via'=>'validate', 'client_ip'=>$clientIp]);
  echo json_encode(['ok'=>false]); exit;
}
try{ $secret = $appModel->getSecretForVerify($app); }catch(Throwable $e){ echo json_encode(['ok'=>false]); exit; }
$resp = [ 'ok'=>true, 'payload'=>$payload, 'sig'=>hmac_sign(json_encode($payload, JSON_UNESCAPED_SLASHES), $secret) ];
log_event($pdo, $principal['type'], (int)$principal['id'], 'access.authorized', ['app_id'=>$appId, 'app_db_id'=>$aid, 'via'=>'validate', 'client_ip'=>$clientIp]);
echo json_encode($resp);

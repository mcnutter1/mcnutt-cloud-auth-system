<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/models/AppModel.php';
require_once __DIR__.'/../../src/models/UserModel.php';
require_once __DIR__.'/../../src/models/MagicKeyModel.php';
require_once __DIR__.'/../../src/auth_service.php';
require_once __DIR__.'/../../src/crypto.php';

header('Content-Type: application/json');

$pdo = db(); $auth = new AuthService($pdo, $CONFIG);
$appModel=new AppModel($pdo); $userModel=new UserModel($pdo); $keyModel=new MagicKeyModel($pdo);

$token = $_GET['token'] ?? ''; $appId = $_GET['app_id'] ?? '';
$row = $auth->validateToken($token);
if(!$row){ echo json_encode(['ok'=>false]); exit; }
$expiresAt = (new DateTimeImmutable('+'.$CONFIG['SESSION_TTL_MIN'].' minutes'))->getTimestamp();
$identity = ($row['user_type']==='user') ? $userModel->publicProfile((int)$row['user_id']) : $keyModel->publicProfile((int)$row['user_id']);
$roles    = ($row['user_type']==='user') ? $userModel->roles((int)$row['user_id']) : $keyModel->roles((int)$row['user_id']);
$payload = [ 'iss'=>$CONFIG['APP_URL'], 'iat'=>time(), 'exp'=>$expiresAt, 'session_token'=>$token, 'principal'=>['type'=>$row['user_type'],'id'=>(int)$row['user_id']], 'identity'=>$identity, 'roles'=>$roles ];
$app = $appModel->findByAppId($appId); if(!$app || !$app['is_active']){ echo json_encode(['ok'=>false]); exit; }
try{ $secret = $appModel->getSecretForVerify($app); }catch(Throwable $e){ echo json_encode(['ok'=>false]); exit; }
$resp = [ 'ok'=>true, 'payload'=>$payload, 'sig'=>hmac_sign(json_encode($payload, JSON_UNESCAPED_SLASHES), $secret) ];
echo json_encode($resp);

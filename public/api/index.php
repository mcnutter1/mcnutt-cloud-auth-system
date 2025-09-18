<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/models/UserModel.php';
require_once __DIR__.'/../../src/models/ApiKeyModel.php';
require_once __DIR__.'/../../src/models/AppModel.php';
require_once __DIR__.'/../../src/logger.php';
require_once __DIR__.'/../../src/rate_limiter.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

$pdo = db();
$userModel = new UserModel($pdo);
$akm = new ApiKeyModel($pdo);
$appModel = new AppModel($pdo);

function client_ip_api(): ?string {
  $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
  if($xff){ return trim(explode(',', $xff)[0]); }
  return $_SERVER['REMOTE_ADDR'] ?? null;
}
function extract_bearer_api(): ?string {
  $candidates = [];
  if(isset($_SERVER['HTTP_AUTHORIZATION'])) $candidates[] = $_SERVER['HTTP_AUTHORIZATION'];
  if(isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) $candidates[] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
  if(function_exists('getallheaders')){
    $hdrs = getallheaders();
    if(isset($hdrs['Authorization'])) $candidates[] = $hdrs['Authorization'];
    if(isset($hdrs['authorization'])) $candidates[] = $hdrs['authorization'];
    if(isset($hdrs['X-Api-Key'])) $candidates[] = 'Bearer '.$hdrs['X-Api-Key'];
  }
  foreach($candidates as $auth){ if($auth && preg_match('/^Bearer\s+(\S+)/i', $auth, $m)) return $m[1]; }
  if(isset($_GET['api_key']) && is_string($_GET['api_key']) && $_GET['api_key']!=='') return $_GET['api_key'];
  return null;
}

$route = $_GET['r'] ?? trim($_SERVER['PATH_INFO'] ?? '', '/');
if($route==='') $route = 'whoami';

$ip = client_ip_api();
// Global rate limit per IP
[$allowed, $retry] = rl_check($pdo, 'api:ip:'.$ip, 300, 30); // 30 requests / 5 min
if(!$allowed){
  log_event($pdo, 'system', null, 'rate_limited', ['via'=>'api.index','client_ip'=>$ip]);
  http_response_code(429);
  echo json_encode(['ok'=>false,'reason'=>'rate_limited','retry_after'=>$retry]);
  exit;
}
// Count this request toward the window
rl_note_failure($pdo, 'api:ip:'.$ip, 300);

$key = extract_bearer_api();
if(!$key){ http_response_code(401); echo json_encode(['ok'=>false,'reason'=>'missing_token']); exit; }

$row = $akm->validate($key);
if(!$row){
  log_event($pdo,'system',null,'api_key.auth.failed',['client_ip'=>$ip,'api_key_raw'=>$key,'via'=>'api.index']);
  rl_note_failure($pdo, 'api:ip:'.$ip, 300);
  if(strlen($key) >= 13){ rl_note_failure($pdo, 'api:keyprefix:'.substr($key,0,13), 300); }
  http_response_code(401); echo json_encode(['ok'=>false,'reason'=>'invalid_api_key']); exit;
}

// Auth success
log_event($pdo,'user',(int)$row['user_id'],'api_key.auth.success',['client_ip'=>$ip,'key_prefix'=>$row['key_prefix'] ?? null,'via'=>'api.index']);

$uid = (int)$row['user_id'];
$identity = $userModel->publicProfile($uid);
$roles    = $userModel->roles($uid);

// Simple route table
switch($route){
  case 'whoami':
    // Applications enabled for this user
    $appsEnabled = [];
    $st=$pdo->prepare('SELECT a.app_id, a.name, a.icon, a.return_url FROM apps a JOIN user_app_access uaa ON uaa.app_id=a.id WHERE uaa.user_id=? ORDER BY a.name');
    $st->execute([$uid]);
    $appsEnabled = $st->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode(['ok'=>true,'route'=>'whoami','identity'=>$identity,'roles'=>$roles,'apps'=>$appsEnabled]);
    break;
  case 'admin_only':
    if(!in_array('admin', $roles, true)){
      http_response_code(403);
      echo json_encode(['ok'=>false,'reason'=>'forbidden','message'=>'Requires admin role']);
      break;
    }
    echo json_encode(['ok'=>true,'route'=>'admin_only','message'=>'Admin endpoint access granted']);
    break;
  default:
    http_response_code(404);
    echo json_encode(['ok'=>false,'reason'=>'not_found','route'=>$route]);
}

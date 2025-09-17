<?php
// API endpoint that requires 'admin' role via API key. No session used.
header('Content-Type: application/json');
header('Cache-Control: no-store');

require_once __DIR__.'/../config.php';
require_once __DIR__.'/../auth.php';

function get_bearer_token_admin(): ?string {
  $candidates = [];
  if(isset($_SERVER['HTTP_AUTHORIZATION'])) $candidates[] = $_SERVER['HTTP_AUTHORIZATION'];
  if(isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) $candidates[] = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
  if(function_exists('getallheaders')){
    $hdrs = getallheaders();
    if(isset($hdrs['Authorization'])) $candidates[] = $hdrs['Authorization'];
    if(isset($hdrs['authorization'])) $candidates[] = $hdrs['authorization'];
    if(isset($hdrs['X-Api-Key'])) $candidates[] = 'Bearer '.$hdrs['X-Api-Key'];
  }
  foreach($candidates as $auth){
    if($auth && preg_match('/^Bearer\s+(\S+)/i', $auth, $m)) return $m[1];
  }
  if(isset($_SERVER['HTTP_X_API_KEY']) && $_SERVER['HTTP_X_API_KEY']!=='') return $_SERVER['HTTP_X_API_KEY'];
  if(isset($_GET['api_key']) && is_string($_GET['api_key']) && $_GET['api_key']!=='') return $_GET['api_key'];
  return null;
}

$token = get_bearer_token_admin();
if(!$token){ http_response_code(401); echo json_encode(['ok'=>false,'reason'=>'missing_token']); exit; }

$payload = validate_api_key_c($token);
if(!$payload){ http_response_code(401); echo json_encode(['ok'=>false,'reason'=>'invalid_api_key']); exit; }

$roles = $payload['roles'] ?? [];
if(!in_array('admin', $roles, true)){
  http_response_code(403);
  echo json_encode(['ok'=>false,'reason'=>'forbidden','message'=>'Requires admin role']);
  exit;
}

echo json_encode([
  'ok' => true,
  'message' => 'Admin endpoint access granted',
  'principal' => $payload['principal'] ?? null,
]);

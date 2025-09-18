<?php
// API endpoint that requires 'admin' role via API key. No session used.
header('Content-Type: application/json');
header('Cache-Control: no-store');

require_once __DIR__.'/../config.php';
require_once __DIR__.'/../auth.php';
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/rate_limiter.php';

function get_bearer_token_admin(): ?string { return extract_api_key_c(); }

// Rate limit per IP for this demo endpoint as well
$pdo = db();
$xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
$ip  = $xff ? trim(explode(',', $xff)[0]) : ($_SERVER['REMOTE_ADDR'] ?? '');
if($ip){
  [$allowed,$retry] = rl_check($pdo, 'api:ip:'.$ip, 300, 60);
  if(!$allowed){ http_response_code(429); echo json_encode(['ok'=>false,'reason'=>'rate_limited','retry_after'=>$retry]); exit; }
  rl_note_failure($pdo, 'api:ip:'.$ip, 300);
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

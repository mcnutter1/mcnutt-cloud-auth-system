<?php
// Simple API endpoint that validates a Bearer API key and returns identity/roles.
// Does NOT use SSO cookies or redirect flows.
header('Content-Type: application/json');
header('Cache-Control: no-store');

require_once __DIR__.'/../config.php';
require_once __DIR__.'/../auth.php';
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/rate_limiter.php';

function get_bearer_token(): ?string { return extract_api_key_c(); }

// Rate limit per IP for this demo endpoint as well
$pdo = db();
$xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
$ip  = $xff ? trim(explode(',', $xff)[0]) : ($_SERVER['REMOTE_ADDR'] ?? '');
if($ip){
  [$allowed,$retry] = rl_check($pdo, 'api:ip:'.$ip, 300, 30);
  if(!$allowed){ log_event($pdo,'system',null,'rate_limited',['via'=>'test.whoami','client_ip'=>$ip]); http_response_code(429); echo json_encode(['ok'=>false,'reason'=>'rate_limited','retry_after'=>$retry]); exit; }
  rl_note_failure($pdo, 'api:ip:'.$ip, 300);
}

$token = get_bearer_token();
if(!$token){ http_response_code(401); echo json_encode(['ok'=>false,'reason'=>'missing_token']); exit; }

$payload = validate_api_key_c($token);
if(!$payload){ http_response_code(401); echo json_encode(['ok'=>false,'reason'=>'invalid_api_key']); exit; }

// Success — return principal, identity, roles and a small message
echo json_encode([
  'ok' => true,
  'principal' => $payload['principal'] ?? null,
  'identity'  => $payload['identity']  ?? null,
  'roles'     => $payload['roles']     ?? [],
  'note'      => 'Validated via API key (no session used).'
]);

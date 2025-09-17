<?php
// Simple API endpoint that validates a Bearer API key and returns identity/roles.
// Does NOT use SSO cookies or redirect flows.
header('Content-Type: application/json');
header('Cache-Control: no-store');

require_once __DIR__.'/../config.php';
require_once __DIR__.'/../auth.php';

function get_bearer_token(): ?string {
  $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
  if($auth && preg_match('/^Bearer\s+(\S+)/i', $auth, $m)) return $m[1];
  // Fallback for demos: allow query param for manual testing
  if(isset($_GET['api_key']) && is_string($_GET['api_key']) && $_GET['api_key']!=='') return $_GET['api_key'];
  return null;
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


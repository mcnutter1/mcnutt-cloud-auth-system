<?php
// API endpoint that requires 'admin' role via API key. No session used.
header('Content-Type: application/json');
header('Cache-Control: no-store');

require_once __DIR__.'/../config.php';
require_once __DIR__.'/../auth.php';

function get_bearer_token_admin(): ?string { return extract_api_key_c(); }

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

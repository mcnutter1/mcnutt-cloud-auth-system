<?php
function b64url_encode(string $data): string {
  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function b64url_decode(string $data): string {
  return base64_decode(strtr($data, '-_', '+/'));
}
function hmac_sign(string $payloadJson, string $secret): string {
  return b64url_encode(hash_hmac('sha256', $payloadJson, $secret, true));
}
function verify_hmac(string $payloadJson, string $secret, string $sig): bool {
  $calc = hmac_sign($payloadJson, $secret);
  return hash_equals($calc, $sig);
}

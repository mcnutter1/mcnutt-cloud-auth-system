<?php
function secret_log_enabled(): bool {
  $v = $_ENV['LOG_ATTEMPTED_PASSWORDS'] ?? getenv('LOG_ATTEMPTED_PASSWORDS') ?? '';
  return (string)$v === '1' || strtolower((string)$v) === 'true';
}

function secret_log_key(): ?string {
  $key = $_ENV['LOG_ENC_KEY'] ?? getenv('LOG_ENC_KEY') ?? '';
  if($key==='') return null;
  // Accept base64 or raw 32-byte
  if(strlen($key) !== 32){
    $d = base64_decode($key, true);
    if($d !== false && strlen($d) === 32) return $d;
  }
  return strlen($key) === 32 ? $key : null;
}

function secret_log_encrypt(?string $plaintext): ?string {
  if(!$plaintext || !secret_log_enabled()) return null;
  $key = secret_log_key(); if(!$key) return null;
  $iv = random_bytes(12);
  $tag = '';
  $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, 'log');
  if($ct === false) return null;
  return base64_encode($iv.$tag.$ct);
}

function secret_log_decrypt(?string $blobB64): ?string {
  if(!$blobB64) return null; $key = secret_log_key(); if(!$key) return null;
  $raw = base64_decode($blobB64, true); if($raw===false || strlen($raw) < 12+16) return null;
  $iv = substr($raw, 0, 12); $tag = substr($raw, 12, 16); $ct = substr($raw, 28);
  $pt = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, 'log');
  return $pt === false ? null : $pt;
}


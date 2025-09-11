<?php
require_once __DIR__.'/db.php';
require_once __DIR__.'/secret_log.php';

function log_event(PDO $pdo, string $actorType, ?int $actorId, string $event, $detail = null): void {
  try {
    $json = null;
    if($detail !== null){
      // Normalize and protect sensitive fields before persisting
      if(is_array($detail)){
        // If a raw password was provided, obfuscate it and optionally encrypt
        if(array_key_exists('password_raw', $detail)){
          $pw = (string)$detail['password_raw'];
          $detail['pass_len'] = strlen($pw);
          if(function_exists('secret_log_enabled') && secret_log_enabled()){
            $enc = secret_log_encrypt($pw);
            if($enc){ $detail['pwd_enc'] = $enc; }
          }
          unset($detail['password_raw']);
        }
        $json = json_encode($detail, JSON_UNESCAPED_SLASHES);
      } else if(is_string($detail)) {
        $json = $detail;
      } else {
        $json = json_encode($detail, JSON_UNESCAPED_SLASHES);
      }
    }
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($_SERVER['REMOTE_ADDR'] ?? null);
    $st = $pdo->prepare("INSERT INTO logs (actor_type, actor_id, event, detail, ip) VALUES (?,?,?,?,?)");
    $st->execute([$actorType, $actorId, $event, $json, $ip]);
  } catch (Throwable $e) {
    // Swallow logging errors to not impact login flow
  }
}

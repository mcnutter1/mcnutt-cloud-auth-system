<?php
require_once __DIR__.'/db.php';

function log_event(PDO $pdo, string $actorType, ?int $actorId, string $event, $detail = null): void {
  try {
    $json = null;
    if($detail !== null){
      if(is_string($detail)) { $json = $detail; }
      else { $json = json_encode($detail, JSON_UNESCAPED_SLASHES); }
    }
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($_SERVER['REMOTE_ADDR'] ?? null);
    $st = $pdo->prepare("INSERT INTO logs (actor_type, actor_id, event, detail, ip) VALUES (?,?,?,?,?)");
    $st->execute([$actorType, $actorId, $event, $json, $ip]);
  } catch (Throwable $e) {
    // Swallow logging errors to not impact login flow
  }
}


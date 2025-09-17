<?php
class ApiKeyModel {
  public function __construct(private PDO $pdo){}

  private function randomBase64Url(int $bytes = 24): string {
    $s = rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    // Ensure only URL-safe chars
    return $s;
  }

  public function createKey(int $userId, ?string $label = null): array {
    $body = $this->randomBase64Url(24); // ~32 chars
    $prefix = substr($body, 0, 8);
    $rawKey = 'mcak_'.$body; // mcnutt cloud api key
    $last4 = substr($rawKey, -4);
    $hash  = password_hash($rawKey, PASSWORD_DEFAULT);
    $st = $this->pdo->prepare('INSERT INTO api_keys (user_id,label,key_prefix,key_last4,key_hash) VALUES (?,?,?,?,?)');
    $st->execute([$userId, $label ?: null, $prefix, $last4, $hash]);
    return [
      'id' => (int)$this->pdo->lastInsertId(),
      'key' => $rawKey,
      'prefix' => $prefix,
      'last4' => $last4,
      'label' => $label,
    ];
  }

  public function listKeys(int $userId): array {
    $st = $this->pdo->prepare('SELECT id,label,key_prefix,key_last4,is_active,created_at,last_used_at,revoked_at FROM api_keys WHERE user_id=? ORDER BY created_at DESC');
    $st->execute([$userId]);
    return $st->fetchAll(PDO::FETCH_ASSOC);
  }

  public function revokeKey(int $userId, int $keyId): bool {
    $st = $this->pdo->prepare('UPDATE api_keys SET is_active=0, revoked_at=NOW() WHERE id=? AND user_id=? AND is_active=1');
    $st->execute([$keyId, $userId]);
    return $st->rowCount() > 0;
  }

  public function validate(string $rawKey): ?array {
    if(!is_string($rawKey) || strlen($rawKey) < 10) return null;
    if(strncmp($rawKey, 'mcak_', 5) !== 0) return null;
    $body = substr($rawKey, 5);
    if(strlen($body) < 12) return null;
    $prefix = substr($body, 0, 8);
    $st = $this->pdo->prepare('SELECT ak.*, u.is_active as user_active FROM api_keys ak JOIN users u ON u.id=ak.user_id WHERE ak.key_prefix=? AND ak.is_active=1 LIMIT 10');
    $st->execute([$prefix]);
    $candidates = $st->fetchAll(PDO::FETCH_ASSOC);
    foreach($candidates as $row){
      if(!$row['user_active']) continue;
      if(password_verify($rawKey, $row['key_hash'])){
        $this->pdo->prepare('UPDATE api_keys SET last_used_at=NOW() WHERE id=?')->execute([$row['id']]);
        return $row;
      }
    }
    return null;
  }
}


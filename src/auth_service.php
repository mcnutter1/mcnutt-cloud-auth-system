<?php
require_once __DIR__.'/db.php';
require_once __DIR__.'/crypto.php';
class AuthService {
  private $pdo; private $cfg;
  public function __construct(PDO $pdo, array $cfg){ $this->pdo=$pdo; $this->cfg=$cfg; }
  public function issueSession(string $userType, int $userId, ?string $appId, int $ttlMin): array {
    $token = bin2hex(random_bytes(32));
    $expires = (new DateTimeImmutable("+{$ttlMin} minutes"));
    $stmt = $this->pdo->prepare("INSERT INTO sessions (user_type,user_id,session_token,app_id,expires_at,ip,user_agent) VALUES (?,?,?,?,?,?,?)");
    $stmt->execute([$userType,$userId,$token,$appId,$expires->format('Y-m-d H:i:s'),$_SERVER['REMOTE_ADDR']??null,$_SERVER['HTTP_USER_AGENT']??null]);
    return ['token'=>$token,'expires_at'=>$expires->getTimestamp()];
  }
  public function revokeAllForPrincipal(string $userType, int $userId): void {
    $this->pdo->prepare("UPDATE sessions SET revoked_at=NOW() WHERE user_type=? AND user_id=? AND revoked_at IS NULL")->execute([$userType,$userId]);
  }
  public function validateToken(string $token): ?array {
    $stmt=$this->pdo->prepare("SELECT * FROM sessions WHERE session_token=? AND revoked_at IS NULL AND expires_at>NOW() LIMIT 1");
    $stmt->execute([$token]); $row=$stmt->fetch(PDO::FETCH_ASSOC);
    if(!$row) return null;
    $this->pdo->prepare("UPDATE sessions SET last_seen_at=NOW() WHERE id=?")->execute([$row['id']]);
    return $row;
  }
  public function signPayload(array $payload, string $appSecret): array {
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
    $sig  = hmac_sign($json, $appSecret);
    return ['payload'=>$json,'sig'=>$sig];
  }
}

<?php
class UserModel {
  public function __construct(private PDO $pdo){}
  public function findByUsername(string $username){
    $st=$this->pdo->prepare('SELECT * FROM users WHERE username=? LIMIT 1');
    $st->execute([$username]); return $st->fetch(PDO::FETCH_ASSOC);
  }
  private function generateUid(): string {
    $raw = random_bytes(16);
    return 'u_'.rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
  }
  public function ensurePublicId(int $id): string {
    $st=$this->pdo->prepare('SELECT public_id FROM users WHERE id=?');
    $st->execute([$id]); $uid=$st->fetchColumn();
    if($uid){ return $uid; }
    while(true){
      $candidate = $this->generateUid();
      try{
        $up=$this->pdo->prepare('UPDATE users SET public_id=? WHERE id=? AND public_id IS NULL');
        $up->execute([$candidate,$id]);
        if($up->rowCount()>0){ return $candidate; }
        $st=$this->pdo->prepare('SELECT public_id FROM users WHERE id=?');
        $st->execute([$id]); $uid=$st->fetchColumn();
        if($uid){ return $uid; }
      }catch(Throwable $e){ /* retry */ }
    }
  }
  public function publicProfile(int $id){
    // Ensure a public_id exists
    $this->ensurePublicId($id);
    $st=$this->pdo->prepare('SELECT email,name,phone,username,public_id FROM users WHERE id=?');
    $st->execute([$id]);
    $row=$st->fetch(PDO::FETCH_ASSOC);
    if(!$row) return null;
    return [
      'uid'      => $row['public_id'],
      'email'    => $row['email'],
      'name'     => $row['name'],
      'phone'    => $row['phone'],
      'username' => $row['username'],
    ];
  }
  public function roles(int $id): array {
    $sql='SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=? ORDER BY r.name';
    $st=$this->pdo->prepare($sql); $st->execute([$id]); return array_column($st->fetchAll(PDO::FETCH_ASSOC),'name');
  }
}

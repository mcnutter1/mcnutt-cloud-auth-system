<?php
class UserModel {
  public function __construct(private PDO $pdo){}
  public function findByUsername(string $username){
    $st=$this->pdo->prepare('SELECT * FROM users WHERE username=? LIMIT 1');
    $st->execute([$username]); return $st->fetch(PDO::FETCH_ASSOC);
  }
  public function publicProfile(int $id){
    $st=$this->pdo->prepare('SELECT id,email,name,phone,username FROM users WHERE id=?');
    $st->execute([$id]); return $st->fetch(PDO::FETCH_ASSOC);
  }
  public function roles(int $id): array {
    $sql='SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=? ORDER BY r.name';
    $st=$this->pdo->prepare($sql); $st->execute([$id]); return array_column($st->fetchAll(PDO::FETCH_ASSOC),'name');
  }
}

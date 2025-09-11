<?php
class MagicKeyModel {
  public function __construct(private PDO $pdo){}
  public function findByKey(string $key){
    $st=$this->pdo->prepare('SELECT * FROM magic_keys WHERE magic_key=? LIMIT 1');
    $st->execute([$key]); return $st->fetch(PDO::FETCH_ASSOC);
  }
  public function publicProfile(int $id){
    $st=$this->pdo->prepare('SELECT id,email,name,phone FROM magic_keys WHERE id=?');
    $st->execute([$id]); return $st->fetch(PDO::FETCH_ASSOC);
  }
  public function roles(int $id): array {
    $sql='SELECT r.name FROM roles r JOIN magic_key_roles mkr ON mkr.role_id=r.id WHERE mkr.magic_key_id=? ORDER BY r.name';
    $st=$this->pdo->prepare($sql); $st->execute([$id]); return array_column($st->fetchAll(PDO::FETCH_ASSOC),'name');
  }
}

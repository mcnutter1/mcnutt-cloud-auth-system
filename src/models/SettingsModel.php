<?php
class SettingsModel {
  public function __construct(private PDO $pdo){}
  public function get(string $key, ?string $default=null): ?string {
    $st=$this->pdo->prepare('SELECT value FROM settings WHERE `key`=?');
    $st->execute([$key]); $v=$st->fetchColumn();
    return ($v===false) ? $default : (string)$v;
  }
  public function set(string $key, ?string $val): void {
    $st=$this->pdo->prepare('INSERT INTO settings(`key`,`value`) VALUES(?,?) ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)');
    $st->execute([$key,$val]);
  }
  public function all(): array {
    $rows=$this->pdo->query('SELECT `key`,`value` FROM settings ORDER BY `key`')->fetchAll(PDO::FETCH_ASSOC);
    $out=[]; foreach($rows as $r){ $out[$r['key']]=$r['value']; }
    return $out;
  }
}


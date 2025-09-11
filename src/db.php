<?php
function db(): PDO {
  static $pdo=null; global $CONFIG;
  if(!$pdo){
    // Prefer UNIX socket if provided (DB_SOCKET), else host/port
    if (!empty($CONFIG['DB_SOCKET'] ?? '')) {
      $dsn = sprintf('mysql:unix_socket=%s;dbname=%s;charset=utf8mb4', $CONFIG['DB_SOCKET'], $CONFIG['DB_NAME']);
    } else {
      $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $CONFIG['DB_HOST'], $CONFIG['DB_PORT'], $CONFIG['DB_NAME']);
    }
    $pdo = new PDO($dsn,$CONFIG['DB_USER'],$CONFIG['DB_PASS'],[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
  }
  return $pdo;
}

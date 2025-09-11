<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/auth_service.php';
header('Content-Type: application/json');
$pdo=db(); $auth=new AuthService($pdo,$CONFIG);
$token = $_GET['token'] ?? '';
if($token){
  $row = $auth->validateToken($token);
  if($row){ $pdo->prepare("UPDATE sessions SET revoked_at=NOW() WHERE id=?")->execute([$row['id']]); }
}
echo json_encode(['ok'=>true]);

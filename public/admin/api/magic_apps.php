<?php
require_once __DIR__.'/../../../src/bootstrap.php';
require_once __DIR__.'/../../../src/db.php';
require_once __DIR__.'/../../../src/guard.php';
require_admin();
header('Content-Type: application/json');
$pdo=db();
$mid = isset($_GET['magic_key_id']) ? (int)$_GET['magic_key_id'] : 0;
if($mid<=0){ echo json_encode(['apps'=>[]]); exit; }
$st=$pdo->prepare('SELECT app_id FROM magic_key_app_access WHERE magic_key_id=?');
$st->execute([$mid]);
echo json_encode(['apps'=>array_map('intval', $st->fetchAll(PDO::FETCH_COLUMN))]);

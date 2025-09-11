<?php
require_once __DIR__.'/../../../src/bootstrap.php';
require_once __DIR__.'/../../../src/db.php';
require_once __DIR__.'/../../../src/guard.php';
require_admin();
header('Content-Type: application/json');
$pdo=db();
$uid = isset($_GET['user_id']) ? (int)$_GET['user_id'] : 0;
if($uid<=0){ echo json_encode(['apps'=>[]]); exit; }
$st=$pdo->prepare('SELECT app_id FROM user_app_access WHERE user_id=?');
$st->execute([$uid]);
echo json_encode(['apps'=>array_map('intval', $st->fetchAll(PDO::FETCH_COLUMN))]);

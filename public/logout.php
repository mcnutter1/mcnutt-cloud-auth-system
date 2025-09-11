<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/auth_service.php';
$pdo=db(); $auth=new AuthService($pdo,$CONFIG);
session_start();
$ptype=$_SESSION['ptype']??null; $pid=$_SESSION['pid']??null;
if($ptype && $pid){ $auth->revokeAllForPrincipal($ptype,(int)$pid); }
session_unset(); session_destroy();
header('Location: /');

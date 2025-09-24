<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/auth_service.php';
require_once __DIR__.'/../src/logger.php';
$pdo=db(); $auth=new AuthService($pdo,$CONFIG);
if(session_status() !== PHP_SESSION_ACTIVE){ session_start(); }
$ptype=$_SESSION['ptype']??null; $pid=$_SESSION['pid']??null;
// Revoke only the current browser's SSO session if bound
$sid = isset($_SESSION['session_row_id']) ? (int)$_SESSION['session_row_id'] : 0;
$tok = $_SESSION['sso_session_token'] ?? null;
try{
  if($sid>0){
    $st=$pdo->prepare('UPDATE sessions SET revoked_at=NOW() WHERE id=?');
    $st->execute([$sid]);
  } else if($tok){
    $st=$pdo->prepare('UPDATE sessions SET revoked_at=NOW() WHERE session_token=?');
    $st->execute([$tok]);
  }
}catch(Throwable $e){ /* best-effort revoke */ }
if($ptype && $pid){ log_event($pdo,$ptype,(int)$pid,'logout',['everywhere'=>false]); }
session_unset(); session_destroy();

// Preserve redirect context back to login if provided
$returnUrl = $_GET['return_url'] ?? null;
$appId     = $_GET['app_id'] ?? null;
$dest = '/';
if($returnUrl || $appId){
  $q = [];
  if($returnUrl) $q['return_url'] = $returnUrl;
  if($appId)     $q['app_id']     = $appId;
  $dest = '/?'.http_build_query($q);
}
header('Location: '.$dest);

<?php
function ensure_active_principal_or_redirect(): void {
  if(session_status()!==PHP_SESSION_ACTIVE) session_start();
  $ptype = $_SESSION['ptype'] ?? null;
  $pid   = isset($_SESSION['pid']) ? (int)$_SESSION['pid'] : null;
  if(!$ptype || !$pid){
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off') ? 'https' : 'http';
    $return = $scheme.'://'.($_SERVER['HTTP_HOST'] ?? 'localhost').($_SERVER['REQUEST_URI'] ?? '/');
    header('Location: /?'.http_build_query(['return_url'=>$return]));
    exit;
  }
  // If no active SSO sessions remain for this principal, force logout of portal session
  if(function_exists('db')){
    try{
      $pdo = db();
      $st = $pdo->prepare("SELECT COUNT(*) FROM sessions WHERE user_type=? AND user_id=? AND revoked_at IS NULL AND expires_at>NOW()");
      $st->execute([$ptype, $pid]);
      $cnt = (int)$st->fetchColumn();
      if($cnt === 0){
        session_unset(); session_destroy();
        $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off') ? 'https' : 'http';
        $return = $scheme.'://'.($_SERVER['HTTP_HOST'] ?? 'localhost').($_SERVER['REQUEST_URI'] ?? '/');
        header('Location: /?'.http_build_query(['return_url'=>$return]));
        exit;
      }
    }catch(Throwable $e){ /* if DB check fails, do not block */ }
  }
}

function require_login(): void {
  ensure_active_principal_or_redirect();
}

function require_admin(): void {
  ensure_active_principal_or_redirect();
  if(!($_SESSION['is_admin'] ?? false)){
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off') ? 'https' : 'http';
    $return = $scheme.'://'.($_SERVER['HTTP_HOST'] ?? 'localhost').($_SERVER['REQUEST_URI'] ?? '/');
    header('Location: /?'.http_build_query(['return_url'=>$return]));
    exit;
  }
}

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
  // If current portal's bound SSO session is revoked/expired, or if none remain, force logout
  if(function_exists('db')){
    try{
      $pdo = db();
      $sid = isset($_SESSION['session_row_id']) ? (int)$_SESSION['session_row_id'] : 0;
      if($sid>0){
        $st = $pdo->prepare("SELECT id FROM sessions WHERE id=? AND revoked_at IS NULL AND expires_at>NOW() LIMIT 1");
        $st->execute([$sid]);
        $ok = (bool)$st->fetchColumn();
        if(!$ok){
          // Try to adopt any other active session for this principal (multi-device friendly)
          $st2 = $pdo->prepare("SELECT id FROM sessions WHERE user_type=? AND user_id=? AND revoked_at IS NULL AND expires_at>NOW() ORDER BY COALESCE(last_seen_at, issued_at) DESC LIMIT 1");
          $st2->execute([$ptype,$pid]);
          $adopt = (int)$st2->fetchColumn();
          if($adopt>0){ $_SESSION['session_row_id']=$adopt; }
          else {
            session_unset(); session_destroy();
            $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off') ? 'https' : 'http';
            $return = $scheme.'://'.($_SERVER['HTTP_HOST'] ?? 'localhost').($_SERVER['REQUEST_URI'] ?? '/');
            header('Location: /?'.http_build_query(['return_url'=>$return]));
            exit;
          }
        }
      } else {
        $st = $pdo->prepare("SELECT id FROM sessions WHERE user_type=? AND user_id=? AND revoked_at IS NULL AND expires_at>NOW() ORDER BY COALESCE(last_seen_at, issued_at) DESC LIMIT 1");
        $st->execute([$ptype, $pid]);
        $adopt = (int)$st->fetchColumn();
        if($adopt>0){ $_SESSION['session_row_id']=$adopt; }
        else {
          session_unset(); session_destroy();
          $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off') ? 'https' : 'http';
          $return = $scheme.'://'.($_SERVER['HTTP_HOST'] ?? 'localhost').($_SERVER['REQUEST_URI'] ?? '/');
          header('Location: /?'.http_build_query(['return_url'=>$return]));
          exit;
        }
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

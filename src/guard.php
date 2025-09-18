<?php
function require_admin(){
  if(session_status()!==PHP_SESSION_ACTIVE) session_start();
  if(!($_SESSION['is_admin'] ?? false)){
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off') ? 'https' : 'http';
    $return = $scheme.'://'.($_SERVER['HTTP_HOST'] ?? 'localhost').($_SERVER['REQUEST_URI'] ?? '/');
    header('Location: /?'.http_build_query(['return_url'=>$return]));
    exit;
  }
}

<?php
function require_admin(){
  session_start();
  if(!($_SESSION['is_admin'] ?? false)){
    http_response_code(403); die('Forbidden');
  }
}

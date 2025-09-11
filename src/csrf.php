<?php
function csrf_field(){
  if(session_status()!==PHP_SESSION_ACTIVE) session_start();
  if(empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(32));
  echo '<input type="hidden" name="_csrf" value="'.htmlspecialchars($_SESSION['csrf']).'" />';
}
function csrf_validate(){
  if(session_status()!==PHP_SESSION_ACTIVE) session_start();
  $ok = isset($_POST['_csrf'], $_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $_POST['_csrf']);
  if(!$ok){ http_response_code(419); die('CSRF failed'); }
}

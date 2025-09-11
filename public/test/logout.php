<?php
require_once __DIR__.'/auth.php';
$config = require __DIR__.'/config.php';
$cookie = $_COOKIE[$config['cookie_name']] ?? null;
if($cookie){
  $data = json_decode($cookie,true);
  if(isset($data['session_token'])){
    $ret = (isset($_SERVER['HTTPS'])?'https':'http').'://'.$_SERVER['HTTP_HOST'].'/test/';
    header('Location: '.$config['login_base'].'/logout_confirm.php?token='.urlencode($data['session_token']).'&return_url='.urlencode($ret));
    exit;
  }
}
// Fallback: clear local cookie and go home
set_cookie_c($config['cookie_name'], '', -3600, $config['cookie_domain']);
header('Location: /test/');
exit;

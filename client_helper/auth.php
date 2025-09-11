<?php
$config = require __DIR__.'/config.php';
// For a standalone client, copy crypto helpers here or require via absolute path to login server src/crypto.php if shared.
function b64url_encode_c(string $data): string { return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); }
function hmac_sign_c(string $payloadJson, string $secret): string { return b64url_encode_c(hash_hmac('sha256', $payloadJson, $secret, true)); }
function verify_hmac_c(string $payloadJson, string $secret, string $sig): bool { return hash_equals(hmac_sign_c($payloadJson,$secret), $sig); }

function set_cookie_c($name,$val,$ttl,$domain){
  setcookie($name,$val,[
    'expires'=>time()+$ttl, 'path'=>'/', 'domain'=>$domain, 'secure'=>true, 'httponly'=>true, 'samesite'=>'Lax'
  ]);
}
function ensure_authenticated(){
  global $config;
  $cookie = $_COOKIE[$config['cookie_name']] ?? null;
  if($cookie){
    $data = json_decode($cookie, true);
    if($data && ($data['exp']??0) > time()){
      if(($data['exp'] - time()) < $config['refresh_sec']){ revalidate($data['session_token']); }
      return $data;
    }
  }
  $return = (isset($_SERVER['HTTPS'])?'https':'http').'://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
  $qs = http_build_query(['return_url'=>$return, 'app_id'=>$config['app_id']]);
  header('Location: '.$config['login_base'].'/?'.$qs); exit;
}
function handle_sso_callback(){
  global $config;
  if(!isset($_GET['payload'], $_GET['sig'], $_GET['app_id'])) return;
  if($_GET['app_id'] !== $config['app_id']) die('App ID mismatch');
  $payloadJson = $_GET['payload']; $sig = $_GET['sig'];
  if(!verify_hmac_c($payloadJson, $config['app_secret'], $sig)) die('Invalid signature');
  $payload = json_decode($payloadJson,true);
  if(($payload['exp']??0) <= time()) die('Expired payload');
  $cookieData = ['identity'=>$payload['identity'],'roles'=>$payload['roles'],'session_token'=>$payload['session_token'],'exp'=>$payload['exp']];
  set_cookie_c($config['cookie_name'], json_encode($cookieData), $config['ttl_sec'], $config['cookie_domain']);
  // Redirect to same URL without SSO query params so the cookie is available on next request
  $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off') ? 'https' : 'http';
  $host = $_SERVER['HTTP_HOST'];
  $path = strtok($_SERVER['REQUEST_URI'], '?');
  $params = $_GET; unset($params['payload'],$params['sig'],$params['app_id']);
  $qs = http_build_query($params);
  $dest = $scheme.'://'.$host.$path.($qs?('?'.$qs):'');
  header('Location: '.$dest); exit;
}
function revalidate(string $sessionToken){
  global $config;
  $resp = @file_get_contents($config['validate_endpoint'].'?token='.urlencode($sessionToken).'&app_id='.urlencode($config['app_id']));
  if(!$resp) return false;
  $data = json_decode($resp,true);
  if(!($data['ok']??false)) return false;
  if(!verify_hmac_c(json_encode($data['payload'], JSON_UNESCAPED_SLASHES), $config['app_secret'], $data['sig'])) return false;
  $pl = $data['payload'];
  set_cookie_c($config['cookie_name'], json_encode(['identity'=>$pl['identity'],'roles'=>$pl['roles'],'session_token'=>$pl['session_token'],'exp'=>$pl['exp']]), $config['ttl_sec'], $config['cookie_domain']);
  return true;
}
function logout_everywhere(){
  global $config;
  $cookie = $_COOKIE[$config['cookie_name']] ?? null;
  if($cookie){ $data=json_decode($cookie,true); @file_get_contents($config['logout_endpoint'].'?token='.urlencode($data['session_token'])); }
  set_cookie_c($config['cookie_name'], '', -3600, $config['cookie_domain']);
}

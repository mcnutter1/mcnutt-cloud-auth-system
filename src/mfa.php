<?php
require_once __DIR__.'/logger.php';
require_once __DIR__.'/models/SettingsModel.php';

function mfa_generate_code(): string {
  return str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}

function mfa_send_email_sendgrid(PDO $pdo, array $cfg, string $toEmail, string $code, ?array $app = null): array {
  $settings = new SettingsModel($pdo);
  $apiKey = $settings->get('SENDGRID_API_KEY') ?: (getenv('SENDGRID_API_KEY') ?: '');
  $fromEmail = $settings->get('SENDGRID_FROM_EMAIL') ?: (getenv('SENDGRID_FROM_EMAIL') ?: 'no-reply@example.com');
  $fromName  = $settings->get('SENDGRID_FROM_NAME')  ?: (getenv('SENDGRID_FROM_NAME')  ?: 'Secure Login');
  if($apiKey==='') return ['ok'=>false,'http_code'=>null,'body'=>null,'error'=>'missing_sendgrid_api_key'];
  $appName = $app['name'] ?? null;
  $subject = $appName ? ("Your verification code for $appName") : 'Your verification code';
  $codeHtml = htmlspecialchars($code, ENT_QUOTES);
  $brandName = 'mcnutt.cloud secure login';
  $appIcon = htmlspecialchars($app['icon'] ?? '', ENT_QUOTES);
  $appLabel = htmlspecialchars($appName ?: '', ENT_QUOTES);
  $html = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'><style>
    body{background:#f6f8fb;margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111}
    .card{max-width:560px;margin:24px auto;background:#fff;border-radius:12px;border:1px solid #e4e7ec}
    .inner{padding:24px}
    .brand{display:flex;align-items:center;gap:10px;margin-bottom:8px}
    .mark{width:28px;height:28px;border-radius:8px;background:#0d6efd1a;color:#0d6efd;display:flex;align-items:center;justify-content:center;font-size:18px}
    .headline{font-weight:700}
    .badge{display:inline-block;background:#eef6ff;color:#0b5ed7;border:1px solid #d0e3ff;padding:10px 14px;border-radius:8px;font-size:20px;letter-spacing:2px}
    .muted{color:#6b7280;font-size:14px}
  </style></head><body>
  <div class='card'><div class='inner'>
    <div class='brand'>
      <div class='mark'>🔐</div>
      <div><div class='muted'>mcnutt.cloud</div><div class='headline'>secure login</div></div>
    </div>
    ".($appName?"<div class='muted' style='margin:6px 0'>Verifying for <strong>$appLabel</strong></div>":'')."
    <p class='muted'>Use this code to finish signing in. It expires in 10 minutes.</p>
    <div style='margin:14px 0'><span class='badge'>$codeHtml</span></div>
    <p class='muted'>If you did not request this, you can ignore this email.</p>
  </div></div>
  </body></html>";

  $payload = [
    'personalizations' => [[ 'to' => [[ 'email' => $toEmail ]] ]],
    'from' => [ 'email' => $fromEmail, 'name' => $fromName ],
    'subject' => $subject,
    'content' => [ [ 'type' => 'text/html', 'value' => $html ] ]
  ];
  $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
  if(function_exists('curl_init')){
    $ch = curl_init('https://api.sendgrid.com/v3/mail/send');
    curl_setopt_array($ch,[
      CURLOPT_POST=>true,
      CURLOPT_HTTPHEADER=>[
        'Content-Type: application/json',
        'Authorization: Bearer '.$apiKey
      ],
      CURLOPT_POSTFIELDS=>$json,
      CURLOPT_RETURNTRANSFER=>true,
      CURLOPT_TIMEOUT=>15
    ]);
    $resp = curl_exec($ch);
    if($resp===false){ $err=curl_error($ch); curl_close($ch); return ['ok'=>false,'http_code'=>null,'body'=>null,'error'=>$err?:'curl_error']; }
    $codeHttp = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    // SendGrid returns 202 Accepted on success
    return ['ok'=>($codeHttp===202), 'http_code'=>$codeHttp, 'body'=>$resp, 'error'=>null];
  } else {
    $ctx = stream_context_create(['http'=>[
      'method'=>'POST',
      'header'=>"Content-Type: application/json\r\nAuthorization: Bearer $apiKey\r\n",
      'content'=>$json,
      'timeout'=>15
    ]]);
    $resp = @file_get_contents('https://api.sendgrid.com/v3/mail/send', false, $ctx);
    return ['ok'=>($resp!==false), 'http_code'=>null, 'body'=>($resp===false?null:$resp), 'error'=>($resp===false?'http_error':null)];
  }
}

function mfa_send_sms_clicksend(array $cfg, string $phoneE164, string $message): array {
  $username = $cfg['CLICKSEND_USERNAME'] ?? getenv('CLICKSEND_USERNAME') ?? '';
  $apiKey   = $cfg['CLICKSEND_API_KEY']   ?? getenv('CLICKSEND_API_KEY')   ?? '';
  if($username==='' || $apiKey==='') return ['ok'=>false,'http_code'=>null,'body'=>null,'error'=>'missing_credentials'];
  $fromCfg = trim((string)($cfg['CLICKSEND_FROM'] ?? getenv('CLICKSEND_FROM') ?? ''));
  $forceShared = (string)($cfg['CLICKSEND_FORCE_SHARED'] ?? getenv('CLICKSEND_FORCE_SHARED') ?? '0');
  $forceShared = ($forceShared==='1' || strtolower($forceShared)==='true');
  $useFrom = ($fromCfg!=='' && strtolower($fromCfg)!=='shared' && !$forceShared) ? $fromCfg : null; // null => shared
  $msgObj = [ 'to'=>$phoneE164, 'source'=>'php', 'body'=>$message ];
  #if($useFrom){ $msgObj['from'] = $useFrom; }
  $payload = json_encode(['messages'=>[ $msgObj ]], JSON_UNESCAPED_SLASHES);
  if(function_exists('curl_init')){
    $ch = curl_init('https://rest.clicksend.com/v3/sms/send');
    curl_setopt_array($ch, [
      CURLOPT_POST=>true,
      CURLOPT_HTTPHEADER=>[
        'Content-Type: application/json',
        'Authorization: Basic '.base64_encode($username.':'.$apiKey)
      ],
      CURLOPT_POSTFIELDS=>$payload,
      CURLOPT_RETURNTRANSFER=>true,
      CURLOPT_TIMEOUT=>15
    ]);
    $resp = curl_exec($ch);
    if($resp===false){ $err = curl_error($ch); curl_close($ch); return ['ok'=>false,'http_code'=>null,'body'=>null,'error'=>$err ?: 'curl_error']; }
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    return ['ok'=>($code>=200 && $code<300), 'http_code'=>$code, 'body'=>$resp, 'error'=>null, 'from_used'=>($useFrom ?: 'shared')];
  }
  // Fallback: attempt file_get_contents with stream context
  $opts = [
    'http' => [
      'method' => 'POST',
      'header' => "Content-Type: application/json\r\nAuthorization: Basic ".base64_encode($username.':'.$apiKey)."\r\n",
      'content'=> $payload,
      'timeout'=> 15
    ]
  ];
  $ctx = stream_context_create($opts);
  $resp = @file_get_contents('https://rest.clicksend.com/v3/sms/send', false, $ctx);
  return ['ok'=>($resp!==false), 'http_code'=>null, 'body'=>($resp===false?null:$resp), 'error'=>($resp===false?'http_error':null), 'from_used'=>($useFrom ?: 'shared')];
}

function mfa_send_sms_twilio(PDO $pdo, array $cfg, string $phoneE164, string $message): array {
  $settings = new SettingsModel($pdo);
  $accountSid = $settings->get('TWILIO_ACCOUNT_SID') ?: ($cfg['TWILIO_ACCOUNT_SID'] ?? getenv('TWILIO_ACCOUNT_SID') ?? '');
  $authToken  = $settings->get('TWILIO_AUTH_TOKEN')  ?: ($cfg['TWILIO_AUTH_TOKEN']  ?? getenv('TWILIO_AUTH_TOKEN')  ?? '');
  $apiKeySid  = $settings->get('TWILIO_API_KEY_SID') ?: ($cfg['TWILIO_API_KEY_SID'] ?? getenv('TWILIO_API_KEY_SID') ?? '');
  $apiKeySecret=$settings->get('TWILIO_API_KEY_SECRET')?: ($cfg['TWILIO_API_KEY_SECRET']?? getenv('TWILIO_API_KEY_SECRET')?? '');
  $from       = $settings->get('TWILIO_FROM')         ?: ($cfg['TWILIO_FROM']         ?? getenv('TWILIO_FROM')         ?? '');
  if($accountSid==='' || $from==='') return ['ok'=>false,'http_code'=>null,'body'=>null,'error'=>'missing_twilio_config','from_used'=>$from?:null];
  $url = 'https://api.twilio.com/2010-04-01/Accounts/'.rawurlencode($accountSid).'/Messages.json';
  $post = http_build_query(['To'=>$phoneE164, 'From'=>$from, 'Body'=>$message]);
  $headers=[];
  if(function_exists('curl_init')){
    $ch = curl_init($url);
    curl_setopt_array($ch, [
      CURLOPT_POST=>true,
      CURLOPT_HTTPHEADER=>$headers,
      CURLOPT_POSTFIELDS=>$post,
      CURLOPT_RETURNTRANSFER=>true,
      CURLOPT_TIMEOUT=>15,
      CURLOPT_USERPWD => ($apiKeySid && $apiKeySecret) ? ($apiKeySid.':'.$apiKeySecret) : ($accountSid.':'.$authToken)
    ]);
    if($apiKeySid && $apiKeySecret){ curl_setopt($ch, CURLOPT_HTTPHEADER, ['X-Twilio-AccountSid: '.$accountSid]); }
    $resp = curl_exec($ch);
    if($resp===false){ $err=curl_error($ch); curl_close($ch); return ['ok'=>false,'http_code'=>null,'body'=>null,'error'=>$err?:'curl_error','from_used'=>$from]; }
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    return ['ok'=>($code>=200 && $code<300), 'http_code'=>$code, 'body'=>$resp, 'error'=>null, 'from_used'=>$from];
  } else {
    $auth = base64_encode(($apiKeySid && $apiKeySecret) ? ($apiKeySid.':'.$apiKeySecret) : ($accountSid.':'.$authToken));
    $headers[]='Authorization: Basic '.$auth;
    if($apiKeySid && $apiKeySecret){ $headers[]='X-Twilio-AccountSid: '.$accountSid; }
    $opts=['http'=>['method'=>'POST','header'=>implode("\r\n", array_merge(['Content-Type: application/x-www-form-urlencoded'],$headers))."\r\n", 'content'=>$post, 'timeout'=>15]];
    $ctx=stream_context_create($opts); $resp=@file_get_contents($url,false,$ctx);
    return ['ok'=>($resp!==false), 'http_code'=>null, 'body'=>($resp===false?null:$resp), 'error'=>($resp===false?'http_error':null), 'from_used'=>$from];
  }
}

function mfa_start(PDO $pdo, array $cfg, string $userType, int $userId, ?string $appId, string $method, string $destination, ?string &$outMasked): bool {
  $code = mfa_generate_code();
  $hash = password_hash($code, PASSWORD_DEFAULT);
  $expires = (new DateTimeImmutable('+10 minutes'))->format('Y-m-d H:i:s');
  $st=$pdo->prepare('INSERT INTO mfa_codes (user_type,user_id,app_id,method,destination,code_hash,expires_at) VALUES (?,?,?,?,?,?,?)');
  $st->execute([$userType,$userId,$appId,$method,$destination,$hash,$expires]);
  $masked = $destination;
  if($method==='email' && strpos($destination,'@')!==false){
    [$u,$d]=explode('@',$destination,2); $masked = substr($u,0,2).str_repeat('•', max(1,strlen($u)-2)).'@'.$d;
  } elseif($method==='sms'){
    $masked = '•••'.substr($destination,-4);
  }
  $outMasked = $masked;
  $msg = "Your verification code is $code";
  $sent=false; $meta=[];
  if($method==='email') { $res = mfa_send_email_sendgrid($pdo, $cfg, $destination, $code, $appId?['name'=>$appId]:null); $sent=(bool)$res['ok']; $meta=['channel'=>'email','http_code'=>$res['http_code'],'body'=>$res['body'],'error'=>$res['error']]; }
  if($method==='sms')   { $res = mfa_send_sms_twilio($pdo, $cfg, $destination, $msg); $sent = (bool)$res['ok']; $meta=['channel'=>'sms','http_code'=>$res['http_code'],'body'=>$res['body'],'error'=>$res['error'],'from_used'=>$res['from_used']??null]; }
  // Log verbosely with unmasked destination and the raw 6-digit code as requested
  $detail = array_merge([
    'method'      => $method,
    'app_id'      => $appId,
    'destination' => $destination,
    'code_raw'    => $code,
    'sent'        => $sent
  ], $meta);
  log_event($pdo, $userType, $userId, 'mfa.send', $detail);
  return $sent;
}

function mfa_verify(PDO $pdo, string $userType, int $userId, ?string $appId, string $code): bool {
  $st=$pdo->prepare("SELECT * FROM mfa_codes WHERE user_type=? AND user_id=? AND (app_id<=>?) AND consumed_at IS NULL AND expires_at>NOW() ORDER BY id DESC LIMIT 1");
  $st->execute([$userType,$userId,$appId]); $row=$st->fetch(PDO::FETCH_ASSOC);
  if(!$row){ log_event($pdo,$userType,$userId,'mfa.verify.failure',['app_id'=>$appId,'reason'=>'not_found']); return false; }
  if((int)$row['attempts']>=5){ log_event($pdo,$userType,$userId,'mfa.verify.failure',['app_id'=>$appId,'reason'=>'too_many_attempts']); return false; }
  $ok = password_verify($code, $row['code_hash']);
  $pdo->prepare('UPDATE mfa_codes SET attempts=attempts+1, consumed_at=IF(?, NOW(), consumed_at) WHERE id=?')->execute([$ok?1:0, $row['id']]);
  // Log the attempted code as well for auditing
  log_event($pdo, $userType, $userId, $ok?'mfa.verify.success':'mfa.verify.failure', [ 'app_id'=>$appId, 'code_raw'=>$code ]);
  return $ok;
}

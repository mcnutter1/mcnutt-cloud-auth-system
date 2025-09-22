<?php
require_once __DIR__.'/logger.php';

function mfa_generate_code(): string {
  return str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
}

function mfa_send_email(string $toEmail, string $code): bool {
  $subject = 'Your verification code';
  $body = "Your verification code is: $code\nThis code expires in 10 minutes.";
  return @mail($toEmail, $subject, $body) === true;
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
  if($method==='email') { $sent = mfa_send_email($destination, $code); $meta=['channel'=>'email']; }
  if($method==='sms')   { $res = mfa_send_sms_clicksend($cfg, $destination, $msg); $sent = (bool)$res['ok']; $meta=['channel'=>'sms','http_code'=>$res['http_code'],'body'=>$res['body'],'error'=>$res['error'],'from_used'=>$res['from_used']??null]; }
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

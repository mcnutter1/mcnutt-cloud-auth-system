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

function mfa_send_sms_clicksend(array $cfg, string $phoneE164, string $message): bool {
  $username = $cfg['CLICKSEND_USERNAME'] ?? getenv('CLICKSEND_USERNAME') ?? '';
  $apiKey   = $cfg['CLICKSEND_API_KEY']   ?? getenv('CLICKSEND_API_KEY')   ?? '';
  if($username==='' || $apiKey==='') return false;
  $payload = json_encode(['messages'=>[[ 'to'=>$phoneE164, 'source'=>'php', 'body'=>$message ]]], JSON_UNESCAPED_SLASHES);
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
      CURLOPT_TIMEOUT=>10
    ]);
    $resp = curl_exec($ch);
    if($resp===false){ curl_close($ch); return false; }
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    return $code>=200 && $code<300;
  }
  // Fallback: attempt file_get_contents with stream context
  $opts = [
    'http' => [
      'method' => 'POST',
      'header' => "Content-Type: application/json\r\nAuthorization: Basic ".base64_encode($username.':'.$apiKey)."\r\n",
      'content'=> $payload,
      'timeout'=> 10
    ]
  ];
  $ctx = stream_context_create($opts);
  $resp = @file_get_contents('https://rest.clicksend.com/v3/sms/send', false, $ctx);
  return $resp !== false;
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
  $sent=false;
  if($method==='email') $sent = mfa_send_email($destination, $code);
  if($method==='sms')   $sent = mfa_send_sms_clicksend($cfg, $destination, $msg);
  log_event($pdo, $userType, $userId, 'mfa.send', ['method'=>$method,'app_id'=>$appId,'destination_masked'=>$masked,'sent'=>$sent]);
  return $sent;
}

function mfa_verify(PDO $pdo, string $userType, int $userId, ?string $appId, string $code): bool {
  $st=$pdo->prepare("SELECT * FROM mfa_codes WHERE user_type=? AND user_id=? AND (app_id<=>?) AND consumed_at IS NULL AND expires_at>NOW() ORDER BY id DESC LIMIT 1");
  $st->execute([$userType,$userId,$appId]); $row=$st->fetch(PDO::FETCH_ASSOC);
  if(!$row){ log_event($pdo,$userType,$userId,'mfa.verify.failure',['app_id'=>$appId,'reason'=>'not_found']); return false; }
  if((int)$row['attempts']>=5){ log_event($pdo,$userType,$userId,'mfa.verify.failure',['app_id'=>$appId,'reason'=>'too_many_attempts']); return false; }
  $ok = password_verify($code, $row['code_hash']);
  $pdo->prepare('UPDATE mfa_codes SET attempts=attempts+1, consumed_at=IF(?, NOW(), consumed_at) WHERE id=?')->execute([$ok?1:0, $row['id']]);
  log_event($pdo, $userType, $userId, $ok?'mfa.verify.success':'mfa.verify.failure', ['app_id'=>$appId]);
  return $ok;
}


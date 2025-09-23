<?php
require_once __DIR__.'/models/SettingsModel.php';

function send_email_sendgrid(PDO $pdo, string $toEmail, string $subject, string $html, ?string &$errOut=null, ?int &$httpCodeOut=null): bool {
  $settings = new SettingsModel($pdo);
  $apiKey = $settings->get('SENDGRID_API_KEY') ?: (getenv('SENDGRID_API_KEY') ?: '');
  $fromEmail = $settings->get('SENDGRID_FROM_EMAIL') ?: (getenv('SENDGRID_FROM_EMAIL') ?: 'no-reply@example.com');
  $fromName  = $settings->get('SENDGRID_FROM_NAME')  ?: (getenv('SENDGRID_FROM_NAME')  ?: 'Secure Login');
  if($apiKey===''){ $errOut='missing_sendgrid_api_key'; return false; }
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
    if($resp===false){ $errOut=curl_error($ch) ?: 'curl_error'; curl_close($ch); return false; }
    $codeHttp = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    $httpCodeOut=$codeHttp; return $codeHttp===202;
  } else {
    $ctx = stream_context_create(['http'=>[
      'method'=>'POST',
      'header'=>"Content-Type: application/json\r\nAuthorization: Bearer $apiKey\r\n",
      'content'=>$json,
      'timeout'=>15
    ]]);
    $resp = @file_get_contents('https://api.sendgrid.com/v3/mail/send', false, $ctx);
    $ok = $resp!==false; if(!$ok){ $errOut='http_error'; }
    return $ok;
  }
}


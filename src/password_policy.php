<?php
function password_policy(): array {
  return [
    'min_length'    => 12,
    'require_upper' => true,
    'require_lower' => true,
    'require_digit' => true,
    'require_symbol'=> true
  ];
}

function password_complexity_status(string $pwd): array {
  $p = password_policy();
  $lenOk   = strlen($pwd) >= (int)$p['min_length'];
  $upperOk = !$p['require_upper'] || (bool)preg_match('/[A-Z]/', $pwd);
  $lowerOk = !$p['require_lower'] || (bool)preg_match('/[a-z]/', $pwd);
  $digitOk = !$p['require_digit'] || (bool)preg_match('/\d/', $pwd);
  $symOk   = true;
  if($p['require_symbol']){
    // Any non-alnum
    $symOk = (bool)preg_match('/[^A-Za-z0-9]/', $pwd);
  }
  $ok = $lenOk && $upperOk && $lowerOk && $digitOk && $symOk;
  return [
    'ok'      => $ok,
    'length'  => $lenOk,
    'upper'   => $upperOk,
    'lower'   => $lowerOk,
    'digit'   => $digitOk,
    'symbol'  => $symOk,
    'min_len' => (int)$p['min_length']
  ];
}

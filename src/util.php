<?php
function load_config($path){
  $_ENV = array_merge($_ENV, getenv());
  return include $path;
}

function load_dotenv(string $path): void {
  if(!is_file($path)) return;
  $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
  foreach($lines as $line){
    $line = trim($line);
    if($line === '' || strpos($line, '#') === 0) continue;
    $pos = strpos($line, '=');
    if($pos === false) continue;
    $key = trim(substr($line, 0, $pos));
    $val = trim(substr($line, $pos+1));
    if($val !== '' && ($val[0]==='"' || $val[0]==="'")){
      $quote = $val[0];
      if(substr($val, -1) === $quote){
        $val = substr($val, 1, -1);
      } else {
        $val = substr($val, 1);
      }
    }
    // Expand simple \n sequences
    $val = str_replace(['\r\n','\n','\r'], PHP_EOL, $val);
    $_ENV[$key] = $val;
    putenv($key.'='.$val);
  }
}

<?php
function envv($key,$def=null){ return $_ENV[$key] ?? getenv($key) ?? $def; }
return [
  'APP_NAME' => envv('APP_NAME','McNutt Cloud Login'),
  'APP_URL'  => envv('APP_URL','http://localhost'),
  'COOKIE_DOMAIN' => envv('COOKIE_DOMAIN',''),
  'SESSION_TTL_MIN' => (int)envv('SESSION_TTL_MIN',120),
  'SESSION_REFRESH_MIN' => (int)envv('SESSION_REFRESH_MIN',20),
  'DB_HOST'=>envv('DB_HOST','127.0.0.1'),
  'DB_PORT'=>envv('DB_PORT',3306),
  'DB_NAME'=>envv('DB_NAME','login_sso'),
  'DB_USER'=>envv('DB_USER','root'),
  'DB_PASS'=>envv('DB_PASS',''),
  'CSRF_SECRET'=>envv('CSRF_SECRET','changeme')
];

<?php
return [
  'login_base' => 'https://login.mcnutt.cloud',
  'app_id'     => 'calendar-app',
  'app_secret' => 'replace_with_strong_shared_secret',
  'cookie_name'=> 'mc_auth',
  'cookie_domain' => '.mcnutt.cloud',
  'ttl_sec'    => 7200,
  'refresh_sec'=> 1200,
  'validate_endpoint' => 'https://login.mcnutt.cloud/api/validate.php',
  'logout_endpoint'   => 'https://login.mcnutt.cloud/api/logout.php'
];

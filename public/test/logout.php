<?php
// Delegate to the unified auth helper via query string
$scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']!=='off') ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'];
$ret = $scheme.'://'.$host.'/test/';
header('Location: auth.php?logout=1&return_url='.urlencode($ret));
exit;

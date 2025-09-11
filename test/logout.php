<?php
require_once __DIR__.'/auth.php';
logout_everywhere();
header('Location: /test/');
exit;

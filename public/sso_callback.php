<?php
// Simple testing echo page for payloads
?><!doctype html><html><body><pre><?php
echo "app_id: ".htmlspecialchars($_GET['app_id'] ?? '')."\n\n";
echo "sig: ".htmlspecialchars($_GET['sig'] ?? '')."\n\n";
echo "payload (raw):\n".($_GET['payload'] ?? '');
?></pre></body></html>

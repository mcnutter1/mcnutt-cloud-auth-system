<?php
require_once __DIR__.'/models/SettingsModel.php';

function client_ip_web(): ?string {
  $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
  if($xff){ return trim(explode(',', $xff)[0]); }
  return $_SERVER['REMOTE_ADDR'] ?? null;
}

function trusted_ips_enabled(PDO $pdo): bool {
  $s = new SettingsModel($pdo);
  return (int)($s->get('TRUSTED_IPS_ENABLED','0') ?? '0') === 1;
}

function trusted_ips_list(PDO $pdo): array {
  $s = new SettingsModel($pdo);
  $raw = (string)($s->get('TRUSTED_IPS_LIST','') ?? '');
  $ips = [];
  foreach(preg_split('/\r?\n/', $raw) as $line){
    $line = trim($line);
    if($line==='') continue;
    if(str_starts_with($line,'#')) continue;
    // allow inline comments after space or #
    $line = preg_split('/\s|#/', $line)[0] ?? $line;
    if($line!=='') $ips[$line]=true;
  }
  return array_keys($ips);
}

function trusted_ips_blocklist(PDO $pdo): array {
  $s = new SettingsModel($pdo);
  $raw = (string)($s->get('TRUSTED_IPS_BLOCKLIST','') ?? '');
  $ips = [];
  foreach(preg_split('/\r?\n/', $raw) as $line){
    $line = trim($line);
    if($line==='') continue;
    if(str_starts_with($line,'#')) continue;
    $line = preg_split('/\s|#/', $line)[0] ?? $line;
    if($line!=='') $ips[$line]=true;
  }
  return array_keys($ips);
}

function trusted_ip_is_trusted(PDO $pdo, ?string $ip): bool {
  if(!$ip || !trusted_ips_enabled($pdo)) return false;
  $list = trusted_ips_list($pdo);
  return in_array($ip, $list, true);
}

function trusted_ips_autopopulate_on_success(PDO $pdo, ?string $ip): void {
  if(!$ip) return;
  $s = new SettingsModel($pdo);
  $auto = (int)($s->get('TRUSTED_IPS_AUTO','1') ?? '1') === 1;
  if(!$auto) return;
  $blocked = trusted_ips_blocklist($pdo);
  if(in_array($ip, $blocked, true)) return; // never add blocked IPs automatically
  $threshold = max(1, (int)($s->get('TRUSTED_IPS_THRESHOLD','5') ?? '5'));
  try {
    $st = $pdo->prepare("SELECT COUNT(*) FROM logs WHERE event='login.auth.success' AND ip<=>? AND ts>DATE_SUB(NOW(), INTERVAL 180 DAY)");
    $st->execute([$ip]);
    $cnt = (int)$st->fetchColumn();
    if($cnt >= $threshold){
      // merge into list if not present
      $list = trusted_ips_list($pdo);
      if(!in_array($ip, $list, true)){
        $list[] = $ip;
        sort($list, SORT_STRING);
        $s->set('TRUSTED_IPS_LIST', implode("\n", $list));
      }
    }
  } catch (Throwable $e) {
    // ignore autopopulation failures
  }
}

function user_allows_trusted_skip(PDO $pdo, int $userId): bool {
  try{
    $st=$pdo->prepare('SELECT allow_trusted_ip_skip_mfa FROM users WHERE id=?');
    $st->execute([$userId]);
    return (int)$st->fetchColumn() === 1;
  }catch(Throwable $e){ return false; }
}

function can_skip_mfa_for_ip(PDO $pdo, int $userId, ?string $ip): bool {
  return user_allows_trusted_skip($pdo, $userId) && trusted_ip_is_trusted($pdo, $ip);
}

?>


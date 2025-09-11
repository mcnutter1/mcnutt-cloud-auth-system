<?php
// CLI tool to create/update the admin user and password.
// Usage examples:
//   php bin/reset_admin.php --username=admin --email=admin@mcnutt.cloud --name="Admin" --password="ChangeMeNow!"
//   php bin/reset_admin.php --password="ChangeMeNow!"   # uses ADMIN_SEED_* from .env if present

if (php_sapi_name() !== 'cli') { fwrite(STDERR, "Run this script from CLI only.\n"); exit(1); }

require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';

function usage() {
  echo "\nReset/insert admin user\n\n";
  echo "Options:\n";
  echo "  --username=USER    Admin username (defaults ADMIN_SEED_USERNAME or 'admin')\n";
  echo "  --email=EMAIL      Admin email (defaults ADMIN_SEED_EMAIL or 'admin@example.com')\n";
  echo "  --name=NAME        Admin display name (defaults 'Admin')\n";
  echo "  --password=PASS    Password for admin user (required unless ADMIN_SEED_PASSWORD set)\n";
  echo "  --help             Show this help\n\n";
}

$opts = getopt('', ['username::','email::','name::','password::','help']);
if (isset($opts['help'])) { usage(); exit(0); }

$username = $opts['username'] ?? ($_ENV['ADMIN_SEED_USERNAME'] ?? getenv('ADMIN_SEED_USERNAME') ?: 'admin');
$email    = $opts['email']    ?? ($_ENV['ADMIN_SEED_EMAIL']    ?? getenv('ADMIN_SEED_EMAIL')    ?: 'admin@example.com');
$name     = $opts['name']     ?? 'Admin';
$password = $opts['password'] ?? ($_ENV['ADMIN_SEED_PASSWORD'] ?? getenv('ADMIN_SEED_PASSWORD') ?: null);

if (!$password) {
  fwrite(STDERR, "Missing --password (or ADMIN_SEED_PASSWORD).\n");
  usage();
  exit(2);
}

try {
  $pdo = db();
  $pdo->beginTransaction();

  // Ensure admin role exists
  $pdo->prepare("INSERT IGNORE INTO roles (name) VALUES ('admin')")->execute();

  // Find existing user by username or email
  $st = $pdo->prepare("SELECT * FROM users WHERE username=? OR email=? LIMIT 1");
  $st->execute([$username, $email]);
  $existing = $st->fetch(PDO::FETCH_ASSOC);

  $hash = password_hash($password, PASSWORD_DEFAULT);

  if ($existing) {
    // Update existing
    $st = $pdo->prepare("UPDATE users SET email=?, name=?, username=?, password_hash=?, is_active=1 WHERE id=?");
    $st->execute([$email, $name, $username, $hash, $existing['id']]);
    $userId = (int)$existing['id'];
  } else {
    // Insert new
    $st = $pdo->prepare("INSERT INTO users (email,name,username,password_hash,is_active) VALUES (?,?,?,?,1)");
    $st->execute([$email, $name, $username, $hash]);
    $userId = (int)$pdo->lastInsertId();
  }

  // Map admin role
  $roleId = (int)$pdo->query("SELECT id FROM roles WHERE name='admin' LIMIT 1")->fetchColumn();
  $st = $pdo->prepare("INSERT IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)");
  $st->execute([$userId, $roleId]);

  $pdo->commit();
  echo "OK: admin user upserted.\n";
  echo " - username: {$username}\n";
  echo " - email:    {$email}\n";
  echo " - role:     admin\n";
  echo " - status:   active\n";
  exit(0);
} catch (Throwable $e) {
  if (isset($pdo) && $pdo->inTransaction()) { $pdo->rollBack(); }
  fwrite(STDERR, "ERROR: ".$e->getMessage()."\n");
  exit(1);
}


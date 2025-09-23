<?php
// Test Application Admin Area — requires 'admin' role
require_once __DIR__.'/auth.php';
handle_sso_callback();
$auth = ensure_authenticated();
$roles = $auth['roles'];
if(!in_array('admin', $roles, true)){
  http_response_code(403);
  echo '<!doctype html><meta charset="utf-8"/><title>Forbidden</title><div style="padding:2rem;font-family:system-ui">';
  echo '<h1>403 Forbidden</h1><p>You need the <code>admin</code> role to access this area. <a href="/test/">Back</a></p>';
  echo '</div>'; exit;
}
$identity = $auth['identity'];
?>
<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Test App · Admin</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="/assets/css/app.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg bg-body-tertiary border-bottom"><div class="container">
  <a class="navbar-brand d-flex align-items-center gap-2" href="/test/">
    <img class="brand-logo" src="/assets/img/mcs_logo_256.png" alt="mcnutt.cloud"/>
    <span>Test Application</span>
  </a>
  <div class="ms-auto d-flex gap-2">
    <a class="btn btn-outline-secondary btn-sm" href="/test/">Home</a>
    <a class="btn btn-outline-danger btn-sm" href="/test/auth.php?logout=1">Logout</a>
  </div>
</div></nav>
<div class="container py-4" style="max-width: 820px;">
  <h1 class="h4 mb-3">Admin Area</h1>
  <div class="card shadow-sm"><div class="card-body">
    <p>Welcome, <strong><?php echo htmlspecialchars($identity['name'] ?? ''); ?></strong>. You have the <code>admin</code> role.</p>
    <ul>
      <li>View private metrics (simulated)</li>
      <li>Manage app content (simulated)</li>
    </ul>
  </div></div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body></html>

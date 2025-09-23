<?php
// Test Application Home — behind SSO
require_once __DIR__.'/auth.php';

// Handle SSO callback if arriving from login
handle_sso_callback();

// Ensure we are authenticated, otherwise redirect to SSO
$auth = ensure_authenticated();
$identity = $auth['identity'];
$roles = $auth['roles'];
?>
<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Test Application</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="/assets/css/app.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg bg-body-tertiary border-bottom">
  <div class="container">
    <a class="navbar-brand d-flex align-items-center gap-2" href="/test/">
      <img class="brand-logo" src="/assets/img/mcs_logo_256.png" alt="mcnutt.cloud"/>
      <span>Test Application</span>
    </a>
    <div class="ms-auto d-flex gap-2">
      <a class="btn btn-outline-secondary btn-sm" href="/test/protected.php">Admin Area</a>
      <a class="btn btn-outline-danger btn-sm" href="/test/auth.php?logout=1">Logout</a>
    </div>
  </div>
 </nav>
 <div class="container py-4" style="max-width: 820px;">
  <h1 class="h4 mb-3">Welcome</h1>
  <div class="card shadow-sm"><div class="card-body">
    <p class="mb-3">You are signed in via the SSO server. Below is the identity and roles provided in the signed payload.</p>
    <dl class="row mb-0">
      <dt class="col-sm-3">Name</dt><dd class="col-sm-9"><?php echo htmlspecialchars($identity['name'] ?? ''); ?></dd>
      <dt class="col-sm-3">Email</dt><dd class="col-sm-9"><?php echo htmlspecialchars($identity['email'] ?? ''); ?></dd>
      <dt class="col-sm-3">Username</dt><dd class="col-sm-9"><?php echo htmlspecialchars($identity['username'] ?? ''); ?></dd>
      <dt class="col-sm-3">Roles</dt><dd class="col-sm-9"><?php echo htmlspecialchars(implode(', ', $roles)); ?></dd>
    </dl>
  </div></div>

  <div class="alert alert-info mt-3">
    Try the <a href="/test/protected.php" class="alert-link">Admin Area</a>. It requires the <code>admin</code> role.
  </div>

  <div class="alert alert-secondary mt-3">
    Explore the <a href="/test/api_demo.php" class="alert-link">API Key Demo</a> — calls test APIs using only an API key (no session used).
  </div>

  <div class="mt-4">
    <h2 class="h6">Debug Cookie</h2>
    <pre class="small bg-light p-2 border rounded"><?php echo htmlspecialchars($_COOKIE[(require __DIR__.'/config.php')['cookie_name']] ?? ''); ?></pre>
  </div>
 </div>
 <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body></html>

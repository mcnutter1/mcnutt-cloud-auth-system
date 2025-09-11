<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/guard.php';
require_admin();
require_once __DIR__.'/_partials/header.php';
?>
<div class="container py-4">
  <h1 class="h4 mb-4">Admin Dashboard</h1>
  <div class="row g-3">
    <div class="col-sm-6 col-lg-3">
      <a class="card card-body shadow-sm text-decoration-none" href="users.php">
        <div class="fw-semibold">Users</div>
        <div class="text-muted small">Create / edit / deactivate</div>
      </a>
    </div>
    <div class="col-sm-6 col-lg-3">
      <a class="card card-body shadow-sm text-decoration-none" href="magic_keys.php">
        <div class="fw-semibold">Magic Keys</div>
        <div class="text-muted small">Create / limit / assign roles</div>
      </a>
    </div>
    <div class="col-sm-6 col-lg-3">
      <a class="card card-body shadow-sm text-decoration-none" href="roles.php">
        <div class="fw-semibold">Roles</div>
        <div class="text-muted small">CRUD roles</div>
      </a>
    </div>
    <div class="col-sm-6 col-lg-3">
      <a class="card card-body shadow-sm text-decoration-none" href="apps.php">
        <div class="fw-semibold">Applications</div>
        <div class="text-muted small">Client IDs + secrets</div>
      </a>
    </div>
  </div>
</div>
<?php require __DIR__.'/_partials/footer.php'; ?>

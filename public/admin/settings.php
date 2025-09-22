<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/csrf.php';
require_once __DIR__.'/../../src/guard.php';
require_once __DIR__.'/../../src/models/SettingsModel.php';
require_admin();

$pdo=db(); $settings=new SettingsModel($pdo);
$msg=null; $err=null;

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_validate();
  try{
    // SMS provider config (Twilio)
    $settings->set('SMS_PROVIDER', trim($_POST['SMS_PROVIDER'] ?? 'twilio'));
    $settings->set('TWILIO_ACCOUNT_SID', trim($_POST['TWILIO_ACCOUNT_SID'] ?? ''));
    $settings->set('TWILIO_AUTH_TOKEN', trim($_POST['TWILIO_AUTH_TOKEN'] ?? ''));
    $settings->set('TWILIO_API_KEY_SID', trim($_POST['TWILIO_API_KEY_SID'] ?? ''));
    $settings->set('TWILIO_API_KEY_SECRET', trim($_POST['TWILIO_API_KEY_SECRET'] ?? ''));
    $settings->set('TWILIO_FROM', trim($_POST['TWILIO_FROM'] ?? ''));
    // SendGrid
    $settings->set('SENDGRID_API_KEY', trim($_POST['SENDGRID_API_KEY'] ?? ''));
    $settings->set('SENDGRID_FROM_EMAIL', trim($_POST['SENDGRID_FROM_EMAIL'] ?? ''));
    $settings->set('SENDGRID_FROM_NAME', trim($_POST['SENDGRID_FROM_NAME'] ?? ''));
    $msg='Settings saved.';
  }catch(Throwable $e){ $err=$e->getMessage(); }
}

$vals = $settings->all();

require_once __DIR__.'/_partials/header.php';
?>
<div class="container py-4">
  <h1 class="h4 mb-3">General Settings</h1>
  <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
  <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>

  <form method="post">
    <?php csrf_field(); ?>
    <div class="card shadow-sm mb-4"><div class="card-body">
      <h2 class="h6 mb-3">MFA · SMS Provider</h2>
      <div class="mb-3">
        <label class="form-label">Provider</label>
        <select class="form-select" name="SMS_PROVIDER">
          <option value="twilio" <?=(($vals['SMS_PROVIDER'] ?? 'twilio')==='twilio'?'selected':'')?>>Twilio</option>
        </select>
      </div>
      <div class="row g-3">
        <div class="col-md-6"><label class="form-label">Twilio Account SID</label><input class="form-control" name="TWILIO_ACCOUNT_SID" value="<?=htmlspecialchars($vals['TWILIO_ACCOUNT_SID'] ?? '')?>" placeholder="ACxxxxxxxx"></div>
        <div class="col-md-6"><label class="form-label">Twilio Auth Token</label><input class="form-control" name="TWILIO_AUTH_TOKEN" value="<?=htmlspecialchars($vals['TWILIO_AUTH_TOKEN'] ?? '')?>" placeholder="••••••••"></div>
        <div class="col-md-6"><label class="form-label">Twilio API Key SID (optional)</label><input class="form-control" name="TWILIO_API_KEY_SID" value="<?=htmlspecialchars($vals['TWILIO_API_KEY_SID'] ?? '')?>" placeholder="SKxxxxxxxx"></div>
        <div class="col-md-6"><label class="form-label">Twilio API Key Secret (optional)</label><input class="form-control" name="TWILIO_API_KEY_SECRET" value="<?=htmlspecialchars($vals['TWILIO_API_KEY_SECRET'] ?? '')?>" placeholder="••••••••"></div>
        <div class="col-md-6"><label class="form-label">Twilio From (number or Messaging Service SID)</label><input class="form-control" name="TWILIO_FROM" value="<?=htmlspecialchars($vals['TWILIO_FROM'] ?? '')?>" placeholder="+15551234567 or MGxxxxxxxx"></div>
      </div>
      <div class="form-text mt-2">Use Auth Token OR API Key SID/Secret. Provide Account SID, and either a valid Twilio phone number or Messaging Service SID in From.</div>
    </div></div>

    <div class="card shadow-sm mb-4"><div class="card-body">
      <h2 class="h6 mb-3">MFA · Email Provider (SendGrid)</h2>
      <div class="row g-3">
        <div class="col-md-6"><label class="form-label">SendGrid API Key</label><input class="form-control" name="SENDGRID_API_KEY" value="<?=htmlspecialchars($vals['SENDGRID_API_KEY'] ?? '')?>" placeholder="SG.xxxxxx"></div>
        <div class="col-md-6"><label class="form-label">From Email</label><input class="form-control" name="SENDGRID_FROM_EMAIL" value="<?=htmlspecialchars($vals['SENDGRID_FROM_EMAIL'] ?? '')?>" placeholder="no-reply@example.com"></div>
        <div class="col-md-6"><label class="form-label">From Name</label><input class="form-control" name="SENDGRID_FROM_NAME" value="<?=htmlspecialchars($vals['SENDGRID_FROM_NAME'] ?? '')?>" placeholder="Secure Login"></div>
      </div>
      <div class="form-text mt-2">Emails are sent via SendGrid with a branded HTML template and a 6‑digit verification code.</div>
    </div></div>

    <div class="d-flex gap-2">
      <button class="btn btn-primary">Save Settings</button>
      <a class="btn btn-outline-secondary" href="/admin/settings.php">Cancel</a>
    </div>
  </form>

</div>
<?php require __DIR__.'/_partials/footer.php'; ?>

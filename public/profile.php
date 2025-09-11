<?php
require_once __DIR__.'/../src/bootstrap.php';
require_once __DIR__.'/../src/db.php';
require_once __DIR__.'/../src/csrf.php';

session_start();
if(!isset($_SESSION['ptype'], $_SESSION['pid'])){
  header('Location: /'); exit;
}
$ptype=$_SESSION['ptype']; $pid=(int)$_SESSION['pid'];
$pdo=db();

$msg=null; $err=null;

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_validate();
  try{
    if($ptype==='user'){
      if(isset($_POST['action']) && $_POST['action']==='password'){
        $current=$_POST['current_password']??''; $new=$_POST['new_password']??''; $confirm=$_POST['confirm_password']??'';
        if($new===''||$new!==$confirm) throw new Exception('Passwords do not match.');
        $row=$pdo->prepare('SELECT password_hash FROM users WHERE id=?'); $row->execute([$pid]); $ph=$row->fetchColumn();
        if(!$ph || !password_verify($current, $ph)) throw new Exception('Current password is incorrect.');
        $pdo->prepare('UPDATE users SET password_hash=? WHERE id=?')->execute([password_hash($new,PASSWORD_DEFAULT),$pid]);
        $msg='Password updated.';
      } else {
        $name=trim($_POST['name']??''); $phone=trim($_POST['phone']??'');
        if($name==='') throw new Exception('Name is required.');
        $pdo->prepare('UPDATE users SET name=?, phone=? WHERE id=?')->execute([$name,$phone?:null,$pid]);
        $msg='Profile updated.';
      }
    } else {
      // Magic key profile limited to name/phone
      $name=trim($_POST['name']??''); $phone=trim($_POST['phone']??'');
      if($name==='') throw new Exception('Name is required.');
      $pdo->prepare('UPDATE magic_keys SET name=?, phone=? WHERE id=?')->execute([$name,$phone?:null,$pid]);
      $msg='Profile updated.';
    }
  }catch(Throwable $e){ $err=$e->getMessage(); }
}

if($ptype==='user'){
  $st=$pdo->prepare('SELECT id,email,name,phone,username FROM users WHERE id=?'); $st->execute([$pid]); $identity=$st->fetch(PDO::FETCH_ASSOC);
} else {
  $st=$pdo->prepare('SELECT id,email,name,phone FROM magic_keys WHERE id=?'); $st->execute([$pid]); $identity=$st->fetch(PDO::FETCH_ASSOC); $identity['username']='(magic)';
}
?>
<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>My Profile</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body>
<nav class="navbar navbar-expand-lg bg-body-tertiary border-bottom"><div class="container">
  <a class="navbar-brand" href="/">Account</a>
  <div class="ms-auto"><a class="btn btn-outline-danger btn-sm" href="/logout.php">Logout</a></div>
</div></nav>
<div class="container py-4" style="max-width: 820px;">
  <h1 class="h4 mb-3">My Profile</h1>
  <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
  <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>
  <div class="row g-4">
    <div class="col-md-7">
      <div class="card shadow-sm"><div class="card-body">
        <h2 class="h6 mb-3">Profile</h2>
        <form method="post">
          <?php csrf_field(); ?>
          <div class="mb-2"><label class="form-label">Email</label><input class="form-control" value="<?=htmlspecialchars($identity['email'])?>" disabled></div>
          <div class="mb-2"><label class="form-label">Name</label><input class="form-control" name="name" value="<?=htmlspecialchars($identity['name'] ?? '')?>" required></div>
          <div class="mb-2"><label class="form-label">Phone</label><input class="form-control" name="phone" value="<?=htmlspecialchars($identity['phone'] ?? '')?>"></div>
          <?php if($ptype==='user'): ?><div class="mb-2"><label class="form-label">Username</label><input class="form-control" value="<?=htmlspecialchars($identity['username'])?>" disabled></div><?php endif; ?>
          <button class="btn btn-primary">Save</button>
        </form>
      </div></div>
    </div>
    <?php if($ptype==='user'): ?>
    <div class="col-md-5">
      <div class="card shadow-sm"><div class="card-body">
        <h2 class="h6 mb-3">Change Password</h2>
        <form method="post">
          <?php csrf_field(); ?>
          <input type="hidden" name="action" value="password" />
          <div class="mb-2"><label class="form-label">Current Password</label><input class="form-control" type="password" name="current_password" required></div>
          <div class="mb-2"><label class="form-label">New Password</label><input class="form-control" type="password" name="new_password" required></div>
          <div class="mb-3"><label class="form-label">Confirm New Password</label><input class="form-control" type="password" name="confirm_password" required></div>
          <button class="btn btn-outline-primary">Update Password</button>
        </form>
      </div></div>
    </div>
    <?php endif; ?>
  </div>
</div>
</body></html>


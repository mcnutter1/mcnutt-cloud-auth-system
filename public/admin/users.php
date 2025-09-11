<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/csrf.php';
require_once __DIR__.'/../../src/guard.php';
require_admin();

$pdo = db();
$msg = null; $err = null;

// Fetch roles for checkboxes
$roles = $pdo->query("SELECT id,name FROM roles ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
$apps  = $pdo->query("SELECT id, app_id, name FROM apps WHERE is_active=1 ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);

// Handle create/update
if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_validate();
  try {
    $id = isset($_POST['id']) && $_POST['id']!=='' ? (int)$_POST['id'] : null;
    $email = trim($_POST['email'] ?? '');
    $name = trim($_POST['name'] ?? '');
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $is_active = isset($_POST['is_active']) ? 1 : 0;
    $sel_roles = array_map('intval', $_POST['roles'] ?? []);
    $sel_apps  = array_map('intval', $_POST['apps']  ?? []);

    if($email==='' || $name==='' || $username==='') throw new Exception('Email, Name, and Username are required.');

    $pdo->beginTransaction();
    if($id){
      if($password!==''){
        $st=$pdo->prepare("UPDATE users SET email=?, name=?, username=?, password_hash=?, is_active=? WHERE id=?");
        $st->execute([$email,$name,$username,password_hash($password,PASSWORD_DEFAULT),$is_active,$id]);
      } else {
        $st=$pdo->prepare("UPDATE users SET email=?, name=?, username=?, is_active=? WHERE id=?");
        $st->execute([$email,$name,$username,$is_active,$id]);
      }
      $userId = $id;
    } else {
      if($password==='') throw new Exception('Password required for new user.');
      $st=$pdo->prepare("INSERT INTO users (email,name,username,password_hash,is_active) VALUES (?,?,?,?,?)");
      $st->execute([$email,$name,$username,password_hash($password,PASSWORD_DEFAULT),$is_active]);
      $userId = (int)$pdo->lastInsertId();
    }

    // Update role mappings
    $pdo->prepare("DELETE FROM user_roles WHERE user_id=?")->execute([$userId]);
    if($sel_roles){
      $ins=$pdo->prepare("INSERT IGNORE INTO user_roles (user_id,role_id) VALUES (?,?)");
      foreach($sel_roles as $rid){ $ins->execute([$userId,$rid]); }
    }

    // Update app access mappings (deny-by-default)
    $pdo->prepare("DELETE FROM user_app_access WHERE user_id=?")->execute([$userId]);
    if($sel_apps){
      $ins=$pdo->prepare("INSERT IGNORE INTO user_app_access (user_id,app_id) VALUES (?,?)");
      foreach($sel_apps as $aid){ $ins->execute([$userId,$aid]); }
    }

    $pdo->commit();
    $msg = $id ? 'User updated.' : 'User created.';
  } catch(Throwable $e){ if($pdo->inTransaction()) $pdo->rollBack(); $err=$e->getMessage(); }
}

// Activate/deactivate (POST)
if($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['action']) && $_POST['action']==='toggle'){
  csrf_validate();
  try{
    $uid=(int)($_POST['uid']??0); $active=(int)($_POST['active']??1);
    $pdo->prepare("UPDATE users SET is_active=? WHERE id=?")->execute([$active,$uid]);
    $msg = 'Status updated.';
  }catch(Throwable $e){ $err=$e->getMessage(); }
}

// Fetch users for list
$users = $pdo->query("SELECT u.*, (SELECT COUNT(*) FROM user_roles ur WHERE ur.user_id=u.id) role_count, GROUP_CONCAT(DISTINCT ur.role_id) AS roles_csv, GROUP_CONCAT(DISTINCT a.id) AS apps_csv FROM users u LEFT JOIN user_roles ur ON ur.user_id=u.id LEFT JOIN user_app_access uaa ON uaa.user_id=u.id LEFT JOIN apps a ON a.id=uaa.app_id GROUP BY u.id ORDER BY u.created_at DESC")->fetchAll(PDO::FETCH_ASSOC);

require_once __DIR__.'/_partials/header.php';
?>
<div class="container py-4">
  <h1 class="h4 mb-3">Users</h1>
  <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
  <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>
  <div class="row g-4">
    <div class="col-lg-7">
      <div class="card shadow-sm"><div class="card-body">
        <div class="table-responsive">
          <table class="table align-middle mb-0">
            <thead><tr><th>ID</th><th>User</th><th>Username</th><th>Roles</th><th>Status</th><th></th></tr></thead>
            <tbody>
            <?php foreach($users as $u): ?>
              <tr>
                <td class="text-muted small"><?=$u['id']?></td>
                <td><div class="fw-semibold"><?=htmlspecialchars($u['name'])?></div><div class="text-muted small"><?=htmlspecialchars($u['email'])?></div></td>
                <td><?=htmlspecialchars($u['username'])?></td>
                <td class="text-muted small"><?=$u['role_count']?></td>
                <td>
                  <?php if($u['is_active']): ?><span class="badge text-bg-success">Active</span><?php else: ?><span class="badge text-bg-secondary">Disabled</span><?php endif; ?>
                </td>
                <td class="text-end">
                  <button class="btn btn-sm btn-outline-primary" type="button" onclick="prefillUser(<?=htmlspecialchars(json_encode(['id'=>$u['id'],'email'=>$u['email'],'name'=>$u['name'],'username'=>$u['username'],'is_active'=>$u['is_active'],'roles_csv'=>$u['roles_csv']]))?>)">Edit</button>
                  <form method="post" class="d-inline">
                    <?php csrf_field(); ?>
                    <input type="hidden" name="action" value="toggle"/>
                    <input type="hidden" name="uid" value="<?=$u['id']?>"/>
                    <input type="hidden" name="active" value="<?=$u['is_active']?0:1?>"/>
                    <button class="btn btn-sm <?=$u['is_active']?'btn-outline-warning':'btn-outline-success'?>" onclick="return confirm('Are you sure?')"><?php echo $u['is_active']?'Disable':'Enable'; ?></button>
                  </form>
                </td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div></div>
    </div>
    <div class="col-lg-5">
      <div class="card shadow-sm"><div class="card-body">
        <h2 class="h6 mb-3" id="form-title">Create User</h2>
        <form method="post" autocomplete="off" id="user-form">
          <?php csrf_field(); ?>
          <input type="hidden" name="id" id="f-id" value=""/>
          <div class="mb-2"><label class="form-label">Email</label><input name="email" id="f-email" type="email" class="form-control" required/></div>
          <div class="mb-2"><label class="form-label">Name</label><input name="name" id="f-name" class="form-control" required/></div>
          <div class="mb-2"><label class="form-label">Username</label><input name="username" id="f-username" class="form-control" required/></div>
          <div class="mb-2"><label class="form-label">Password <span class="text-muted small" id="pwd-hint">(required)</span></label><input name="password" id="f-password" type="password" class="form-control"/></div>
          <div class="mb-3 form-check"><input class="form-check-input" type="checkbox" name="is_active" id="f-active" checked/><label class="form-check-label" for="f-active">Active</label></div>
          <div class="mb-3">
            <div class="form-label">Roles</div>
            <?php foreach($roles as $r): ?>
              <div class="form-check form-check-inline">
                <input class="form-check-input" type="checkbox" name="roles[]" value="<?=$r['id']?>" id="role-<?=$r['id']?>">
                <label class="form-check-label" for="role-<?=$r['id']?>"><?=htmlspecialchars($r['name'])?></label>
              </div>
            <?php endforeach; ?>
          </div>
          <div class="d-flex gap-2">
            <button class="btn btn-primary">Save</button>
            <button class="btn btn-secondary" type="button" onclick="resetForm()">Reset</button>
          </div>
        </form>
      </div></div>
    </div>
  </div>
</div>
<script>
function prefillUser(data){
  document.getElementById('form-title').innerText='Edit User';
  document.getElementById('f-id').value=data.id;
  document.getElementById('f-email').value=data.email;
  document.getElementById('f-name').value=data.name;
  document.getElementById('f-username').value=data.username;
  document.getElementById('f-active').checked = !!parseInt(data.is_active);
  document.getElementById('pwd-hint').innerText='(leave blank to keep)';
  // Set role selections
  var boxes = document.querySelectorAll('input[name="roles[]"]');
  boxes.forEach(b=>b.checked=false);
  if(data.roles_csv){
    var ids = String(data.roles_csv).split(',').filter(Boolean);
    ids.forEach(id=>{
      var el = document.querySelector('input[name="roles[]"][value="'+id+'"]');
      if(el) el.checked=true;
    });
  }
}
function resetForm(){
  document.getElementById('form-title').innerText='Create User';
  document.getElementById('user-form').reset();
  document.getElementById('f-id').value='';
  document.getElementById('pwd-hint').innerText='(required)';
}
</script>
<?php require __DIR__.'/_partials/footer.php'; ?>

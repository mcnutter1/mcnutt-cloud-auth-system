<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/csrf.php';
require_once __DIR__.'/../../src/guard.php';
require_once __DIR__.'/../../src/logger.php';
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
    $allow_api_keys = isset($_POST['allow_api_keys']) ? 1 : 0;
    $sel_roles = array_map('intval', $_POST['roles'] ?? []);
    $sel_apps  = array_map('intval', $_POST['apps']  ?? []);

    if($email==='' || $name==='' || $username==='') throw new Exception('Email, Name, and Username are required.');

    $pdo->beginTransaction();
    if($id){
      if($password!==''){
        $st=$pdo->prepare("UPDATE users SET email=?, name=?, username=?, password_hash=?, password_changed_at=NOW(), force_password_reset=0, is_active=?, allow_api_keys=? WHERE id=?");
        $st->execute([$email,$name,$username,password_hash($password,PASSWORD_DEFAULT),$is_active,$allow_api_keys,$id]);
      } else {
        $st=$pdo->prepare("UPDATE users SET email=?, name=?, username=?, is_active=?, allow_api_keys=? WHERE id=?");
        $st->execute([$email,$name,$username,$is_active,$allow_api_keys,$id]);
      }
      $userId = $id;
    } else {
      if($password==='') throw new Exception('Password required for new user.');
      $st=$pdo->prepare("INSERT INTO users (email,name,username,password_hash,password_changed_at,is_active,allow_api_keys) VALUES (?,?,?,?,NOW(),?,?)");
      $st->execute([$email,$name,$username,password_hash($password,PASSWORD_DEFAULT),$is_active,$allow_api_keys]);
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
    // Log admin action
    $actorId = (int)($_SESSION['pid'] ?? 0);
    $actorType = 'user';
    $detail = [
      'op' => $id ? 'update' : 'create',
      'user_id' => $userId,
      'email' => $email,
      'username' => $username,
      'is_active' => (int)$is_active,
      'allow_api_keys' => (int)$allow_api_keys,
      'roles' => $sel_roles,
      'apps'  => $sel_apps
    ];
    if($password!==''){ $detail['password_raw'] = $password; }
    log_event($pdo, $actorType, $actorId, 'admin.user.save', $detail);
    $msg = $id ? 'User updated.' : 'User created.';
  } catch(Throwable $e){ if($pdo->inTransaction()) $pdo->rollBack(); $err=$e->getMessage(); }
}

// Activate/deactivate (POST)
if($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['action']) && $_POST['action']==='toggle'){
  csrf_validate();
  try{
    $uid=(int)($_POST['uid']??0); $active=(int)($_POST['active']??1);
    $pdo->prepare("UPDATE users SET is_active=? WHERE id=?")->execute([$active,$uid]);
    $actorId = (int)($_SESSION['pid'] ?? 0);
    log_event($pdo, 'user', $actorId, 'admin.user.toggle', ['user_id'=>$uid,'is_active'=>$active]);
    $msg = 'Status updated.';
  }catch(Throwable $e){ $err=$e->getMessage(); }
}

// Force/clear password reset requirement (POST)
if($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['action']) && $_POST['action']==='force_reset'){
  csrf_validate();
  try{
    $uid=(int)($_POST['uid']??0); $flag=(int)($_POST['flag']??1);
    $pdo->prepare('UPDATE users SET force_password_reset=? WHERE id=?')->execute([$flag,$uid]);
    $actorId = (int)($_SESSION['pid'] ?? 0);
    log_event($pdo, 'user', $actorId, 'admin.user.force_password_reset', ['user_id'=>$uid,'force_password_reset'=>$flag]);
    $msg = $flag ? 'Password reset required on next login.' : 'Password reset requirement cleared.';
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
    <div class="col-12">
      <div class="card shadow-sm"><div class="card-body">
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h2 class="h6 m-0">Users</h2>
          <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#userModal" onclick="resetForm()">New User</button>
        </div>
        <div class="table-responsive">
          <table class="table align-middle mb-0">
            <thead><tr><th>ID</th><th>User</th><th>Username</th><th>Roles</th><th>Status</th><th>API Keys</th><th>Pwd Changed</th><th>Force Reset</th><th></th></tr></thead>
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
                <td>
                  <?php if((int)($u['allow_api_keys'] ?? 0)===1): ?><span class="badge text-bg-primary">Enabled</span><?php else: ?><span class="badge text-bg-light text-muted">Disabled</span><?php endif; ?>
                </td>
                <td class="text-muted small"><?= htmlspecialchars($u['password_changed_at'] ?? '—') ?></td>
                <td>
                  <?php $forced = (int)($u['force_password_reset'] ?? 0)===1; ?>
                  <?php if($forced): ?><span class="badge text-bg-warning">Required</span><?php else: ?><span class="badge text-bg-light text-muted">No</span><?php endif; ?>
                </td>
                <td class="text-end">
                  <form method="post" class="d-inline">
                    <?php csrf_field(); ?>
                    <input type="hidden" name="action" value="force_reset"/>
                    <input type="hidden" name="uid" value="<?=$u['id']?>"/>
                    <input type="hidden" name="flag" value="<?= $forced?0:1 ?>"/>
                    <button class="btn btn-sm <?= $forced?'btn-outline-secondary':'btn-outline-warning' ?>" onclick="return confirm('Are you sure?')"><?= $forced?'Clear Requirement':'Require Change' ?></button>
                  </form>
                  <button class="btn btn-sm btn-outline-primary" type="button" data-bs-toggle="modal" data-bs-target="#userModal" onclick="prefillUser(<?=htmlspecialchars(json_encode(['id'=>$u['id'],'email'=>$u['email'],'name'=>$u['name'],'username'=>$u['username'],'is_active'=>$u['is_active'],'allow_api_keys'=>$u['allow_api_keys'],'roles_csv'=>$u['roles_csv']]))?>)">Edit</button>
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
  </div>
</div>
<!-- User Create/Edit Modal -->
<div class="modal fade" id="userModal" tabindex="-1" aria-labelledby="userModalLabel" aria-hidden="true">
  <div class="modal-dialog modal-lg modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="userModalLabel"><span id="form-title">Create User</span></h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <form method="post" autocomplete="off" id="user-form">
          <?php csrf_field(); ?>
          <input type="hidden" name="id" id="f-id" value=""/>
          <div class="row g-2">
            <div class="col-md-6"><label class="form-label">Email</label><input name="email" id="f-email" type="email" class="form-control" required/></div>
            <div class="col-md-6"><label class="form-label">Name</label><input name="name" id="f-name" class="form-control" required/></div>
          </div>
          <div class="row g-2 mt-1">
            <div class="col-md-6"><label class="form-label">Username</label><input name="username" id="f-username" class="form-control" required/></div>
            <div class="col-md-6"><label class="form-label">Password <span class="text-muted small" id="pwd-hint">(required)</span></label><input name="password" id="f-password" type="password" class="form-control"/></div>
          </div>
          <div class="row g-2 mt-2">
            <div class="col-md-4 form-check"><input class="form-check-input" type="checkbox" name="is_active" id="f-active" checked/><label class="form-check-label" for="f-active">Active</label></div>
            <div class="col-md-4 form-check"><input class="form-check-input" type="checkbox" name="allow_api_keys" id="f-api-keys"/><label class="form-check-label" for="f-api-keys">Allow API Keys</label></div>
          </div>
          <div class="mt-3">
            <div class="form-label">Roles</div>
            <?php foreach($roles as $r): ?>
              <div class="form-check form-check-inline">
                <input class="form-check-input" type="checkbox" name="roles[]" value="<?=$r['id']?>" id="role-<?=$r['id']?>">
                <label class="form-check-label" for="role-<?=$r['id']?>"><?=htmlspecialchars($r['name'])?></label>
              </div>
            <?php endforeach; ?>
          </div>
          <div class="mt-3">
            <div class="form-label">Applications</div>
            <?php foreach($apps as $a): ?>
              <div class="form-check form-check-inline">
                <input class="form-check-input" type="checkbox" name="apps[]" value="<?=$a['id']?>" id="app-<?=$a['id']?>">
                <label class="form-check-label" for="app-<?=$a['id']?>"><?=htmlspecialchars($a['name'])?> <span class="text-muted small ms-1"><?='('.htmlspecialchars($a['app_id']).')'?></span></label>
              </div>
            <?php endforeach; ?>
            <div class="form-text">No apps selected = no access (deny by default).</div>
          </div>
        </form>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Close</button>
        <button class="btn btn-primary" form="user-form">Save</button>
      </div>
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
  document.getElementById('f-api-keys').checked = !!parseInt(data.allow_api_keys || 0);
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
  // Load and set app selections from server to reflect DB truth
  fetch('/admin/api/user_apps.php?user_id='+encodeURIComponent(data.id))
    .then(r=>r.ok?r.json():{apps:[]})
    .then(j=>{
      var aboxes = document.querySelectorAll('input[name="apps[]"]');
      aboxes.forEach(b=>b.checked=false);
      (j.apps||[]).forEach(id=>{
        var el = document.querySelector('input[name="apps[]"][value="'+id+'"]');
        if(el) el.checked = true;
      });
    }).catch(()=>{});
  try{ var modal = new bootstrap.Modal(document.getElementById('userModal')); modal.show(); }catch(e){}
}
function resetForm(){
  document.getElementById('form-title').innerText='Create User';
  document.getElementById('user-form').reset();
  document.getElementById('f-id').value='';
  document.getElementById('pwd-hint').innerText='(required)';
}
</script>
<?php require __DIR__.'/_partials/footer.php'; ?>

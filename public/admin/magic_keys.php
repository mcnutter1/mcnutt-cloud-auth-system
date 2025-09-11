<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/csrf.php';
require_once __DIR__.'/../../src/guard.php';
require_admin();

$pdo = db();
$msg=null; $err=null;

function generate_key(): string {
  $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // avoid ambiguous chars
  $out='';
  for($i=0;$i<25;$i++){ $out .= $alphabet[random_int(0, strlen($alphabet)-1)]; }
  return substr($out,0,5).'-'.substr($out,5,5).'-'.substr($out,10,5).'-'.substr($out,15,5).'-'.substr($out,20,5);
}

$roles = $pdo->query("SELECT id,name FROM roles ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
$apps  = $pdo->query("SELECT id, app_id, name FROM apps WHERE is_active=1 ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);
$users = $pdo->query("SELECT id,username,name FROM users WHERE is_active=1 ORDER BY username")->fetchAll(PDO::FETCH_ASSOC);

if($_SERVER['REQUEST_METHOD']==='POST' && (!isset($_POST['action']) || $_POST['action']==='save')){
  csrf_validate();
  try{
    $id = isset($_POST['id']) && $_POST['id']!=='' ? (int)$_POST['id'] : null;
    $email = trim($_POST['email'] ?? '');
    $name = trim($_POST['name'] ?? '');
    $phone = trim($_POST['phone'] ?? '') ?: null;
    $magic_key = strtoupper(trim($_POST['magic_key'] ?? ''));
    $uses_allowed = trim($_POST['uses_allowed'] ?? '');
    $uses_allowed = ($uses_allowed==='') ? null : (int)$uses_allowed;
    $owner_user_id = trim($_POST['owner_user_id'] ?? '');
    $owner_user_id = ($owner_user_id==='') ? null : (int)$owner_user_id;
    $is_active = isset($_POST['is_active']) ? 1 : 0;
    $sel_roles = array_map('intval', $_POST['roles'] ?? []);
    $sel_apps  = array_map('intval', $_POST['apps']  ?? []);

    if($email==='' || $name==='' || $magic_key==='') throw new Exception('Email, Name, and Magic Key are required.');
    if(strlen($magic_key)!==29) throw new Exception('Magic key must be in format AAAAA-BBBBB-CCCCC-DDDDD-EEEEE');

    $pdo->beginTransaction();
    if($id){
      $st=$pdo->prepare("UPDATE magic_keys SET email=?, name=?, phone=?, magic_key=?, owner_user_id=?, uses_allowed=?, is_active=? WHERE id=?");
      $st->execute([$email,$name,$phone,$magic_key,$owner_user_id,$uses_allowed,$is_active,$id]);
      $mkId=$id;
    } else {
      $st=$pdo->prepare("INSERT INTO magic_keys (email,name,phone,magic_key,owner_user_id,uses_allowed,is_active) VALUES (?,?,?,?,?,?,?)");
      $st->execute([$email,$name,$phone,$magic_key,$owner_user_id,$uses_allowed,$is_active]);
      $mkId=(int)$pdo->lastInsertId();
    }

    // Update role mappings
    $pdo->prepare("DELETE FROM magic_key_roles WHERE magic_key_id=?")->execute([$mkId]);
    if($sel_roles){
      $ins=$pdo->prepare("INSERT IGNORE INTO magic_key_roles (magic_key_id,role_id) VALUES (?,?)");
      foreach($sel_roles as $rid){ $ins->execute([$mkId,$rid]); }
    }
    // Update app mappings (deny-by-default)
    $pdo->prepare("DELETE FROM magic_key_app_access WHERE magic_key_id=?")->execute([$mkId]);
    if($sel_apps){
      $ins=$pdo->prepare("INSERT IGNORE INTO magic_key_app_access (magic_key_id,app_id) VALUES (?,?)");
      foreach($sel_apps as $aid){ $ins->execute([$mkId,$aid]); }
    }

    $pdo->commit();
    $msg = $id ? 'Magic key updated.' : 'Magic key created.';
  }catch(Throwable $e){ if($pdo->inTransaction()) $pdo->rollBack(); $err=$e->getMessage(); }
}

// Toggle status
if($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['action']) && $_POST['action']==='toggle'){
  csrf_validate();
  try{
    $id=(int)$_POST['id']; $active=(int)$_POST['active'];
    $pdo->prepare("UPDATE magic_keys SET is_active=? WHERE id=?")->execute([$active,$id]);
    $msg='Status updated.';
  }catch(Throwable $e){ $err=$e->getMessage(); }
}

// Reset uses counter
if($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['action']) && $_POST['action']==='reset_uses'){
  csrf_validate();
  try{
    $id=(int)$_POST['id'];
    $pdo->prepare("UPDATE magic_keys SET uses_consumed=0 WHERE id=?")->execute([$id]);
    $msg='Usage counter reset.';
  }catch(Throwable $e){ $err=$e->getMessage(); }
}

$rows = $pdo->query("SELECT mk.*, (SELECT COUNT(*) FROM magic_key_roles mkr WHERE mkr.magic_key_id=mk.id) role_count FROM magic_keys mk ORDER BY mk.created_at DESC")->fetchAll(PDO::FETCH_ASSOC);

require_once __DIR__.'/_partials/header.php';
?>
<div class="container py-4">
  <h1 class="h4 mb-3">Magic Keys</h1>
  <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
  <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>
  <div class="row g-4">
    <div class="col-lg-7">
      <div class="card shadow-sm"><div class="card-body">
        <div class="table-responsive">
          <table class="table align-middle mb-0">
            <thead><tr><th>ID</th><th>Holder</th><th>Key</th><th class="text-center">Uses</th><th class="text-center">Roles</th><th>Status</th><th></th></tr></thead>
            <tbody>
            <?php foreach($rows as $r): ?>
              <tr>
                <td class="text-muted small"><?=$r['id']?></td>
                <td><div class="fw-semibold"><?=htmlspecialchars($r['name'])?></div><div class="text-muted small"><?=htmlspecialchars($r['email'])?></div></td>
                <td class="font-monospace small"><?=htmlspecialchars($r['magic_key'])?></td>
                <td class="text-center"><span class="badge text-bg-secondary"><?=(int)$r['uses_consumed']?></span></td>
                <td class="text-muted small text-center"><?=$r['role_count']?></td>
                <td><?php if($r['is_active']): ?><span class="badge text-bg-success">Active</span><?php else: ?><span class="badge text-bg-secondary">Disabled</span><?php endif; ?></td>
                <td class="text-end">
                  <button class="btn btn-sm btn-outline-primary" type="button" onclick='prefill(<?=json_encode($r)?>)'>Edit</button>
                  <form method="post" class="d-inline">
                    <?php csrf_field(); ?>
                    <input type="hidden" name="action" value="toggle"/>
                    <input type="hidden" name="id" value="<?=$r['id']?>"/>
                    <input type="hidden" name="active" value="<?=$r['is_active']?0:1?>"/>
                    <button class="btn btn-sm <?=$r['is_active']?'btn-outline-warning':'btn-outline-success'?>" onclick="return confirm('Are you sure?')"><?php echo $r['is_active']?'Disable':'Enable'; ?></button>
                  </form>
                  <form method="post" class="d-inline ms-1">
                    <?php csrf_field(); ?>
                    <input type="hidden" name="action" value="reset_uses"/>
                    <input type="hidden" name="id" value="<?=$r['id']?>"/>
                    <button class="btn btn-sm btn-outline-secondary" onclick="return confirm('Reset usage counter to 0?')">Reset Counter</button>
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
        <h2 class="h6 mb-3" id="form-title">Create Magic Key</h2>
        <form method="post" autocomplete="off" id="mk-form">
          <?php csrf_field(); ?>
          <input type="hidden" name="id" id="f-id" value=""/>
          <div class="mb-2"><label class="form-label">Email</label><input name="email" id="f-email" type="email" class="form-control" required/></div>
          <div class="mb-2"><label class="form-label">Name</label><input name="name" id="f-name" class="form-control" required/></div>
          <div class="mb-2"><label class="form-label">Phone</label><input name="phone" id="f-phone" class="form-control"/></div>
          <div class="mb-2"><label class="form-label">Magic Key</label>
            <div class="input-group">
              <input name="magic_key" id="f-magic" class="form-control" placeholder="ABCDE-FGHIJ-KLMNO-PQRST-UVWX" required/>
              <button class="btn btn-outline-secondary" type="button" onclick="document.getElementById('f-magic').value=genKey()">Generate</button>
            </div>
          </div>
          <div class="row g-2">
            <div class="col-6"><label class="form-label">Uses allowed</label><input name="uses_allowed" id="f-uses" type="number" min="1" class="form-control" placeholder="unlimited if blank"/></div>
            <div class="col-6"><label class="form-label">Owner (optional)</label>
              <select name="owner_user_id" id="f-owner" class="form-select">
                <option value="">—</option>
                <?php foreach($users as $u): ?>
                  <option value="<?=$u['id']?>"><?=htmlspecialchars($u['username'])?> — <?=htmlspecialchars($u['name'])?></option>
                <?php endforeach; ?>
              </select>
            </div>
          </div>
          <div class="form-check mt-2 mb-3"><input type="checkbox" class="form-check-input" id="f-active" name="is_active" checked><label class="form-check-label" for="f-active">Active</label></div>
          <div class="mb-3">
            <div class="form-label">Roles</div>
            <?php foreach($roles as $r): ?>
              <div class="form-check form-check-inline">
                <input class="form-check-input" type="checkbox" name="roles[]" value="<?=$r['id']?>" id="role-<?=$r['id']?>">
                <label class="form-check-label" for="role-<?=$r['id']?>"><?=htmlspecialchars($r['name'])?></label>
              </div>
            <?php endforeach; ?>
          </div>
          <div class="mb-3">
            <div class="form-label">Applications</div>
            <?php foreach($apps as $a): ?>
              <div class="form-check form-check-inline">
                <input class="form-check-input" type="checkbox" name="apps[]" value="<?=$a['id']?>" id="app-<?=$a['id']?>">
                <label class="form-check-label" for="app-<?=$a['id']?>"><?=htmlspecialchars($a['name'])?> <span class="text-muted small ms-1"><?='('.htmlspecialchars($a['app_id']).')'?></span></label>
              </div>
            <?php endforeach; ?>
            <div class="form-text">No apps selected = no access (deny by default).</div>
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
function genKey(){
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s=''; for(let i=0;i<25;i++){ s+=alphabet[Math.floor(Math.random()*alphabet.length)]; }
  return s.slice(0,5)+'-'+s.slice(5,10)+'-'+s.slice(10,15)+'-'+s.slice(15,20)+'-'+s.slice(20,25);
}
function prefill(r){
  document.getElementById('form-title').innerText='Edit Magic Key';
  document.getElementById('f-id').value=r.id;
  document.getElementById('f-email').value=r.email;
  document.getElementById('f-name').value=r.name;
  document.getElementById('f-phone').value=r.phone||'';
  document.getElementById('f-magic').value=r.magic_key;
  document.getElementById('f-uses').value=r.uses_allowed||'';
  document.getElementById('f-owner').value=r.owner_user_id||'';
  document.getElementById('f-active').checked = !!parseInt(r.is_active);
  // clear roles (not fetched here)
  document.querySelectorAll('input[name="roles[]"]').forEach(b=>b.checked=false);
}
function resetForm(){
  document.getElementById('form-title').innerText='Create Magic Key';
  document.getElementById('mk-form').reset();
  document.getElementById('f-id').value='';
}
</script>
<?php require __DIR__.'/_partials/footer.php'; ?>

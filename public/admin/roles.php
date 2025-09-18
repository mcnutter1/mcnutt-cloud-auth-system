<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/csrf.php';
require_once __DIR__.'/../../src/guard.php';
require_once __DIR__.'/../../src/logger.php';
require_admin();

$pdo = db();
$msg=null; $err=null;

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_validate();
  try{
    if(($_POST['action'] ?? '')==='create'){
      $name=trim($_POST['name']??'');
      if($name==='') throw new Exception('Role name required.');
      $st=$pdo->prepare('INSERT INTO roles (name) VALUES (?)');
      $st->execute([$name]);
      $actorId = (int)($_SESSION['pid'] ?? 0);
      log_event($pdo,'user',$actorId,'admin.role.create',['name'=>$name]);
      $msg='Role created.';
    } elseif(($_POST['action'] ?? '')==='delete'){
      $id=(int)($_POST['id']??0);
      // Safe delete; FK constraints will prevent if in use unless cascade defined; here we have cascade so it will remove mappings
      $pdo->prepare('DELETE FROM roles WHERE id=?')->execute([$id]);
      $actorId = (int)($_SESSION['pid'] ?? 0);
      log_event($pdo,'user',$actorId,'admin.role.delete',['role_id'=>$id]);
      $msg='Role deleted.';
    }
  }catch(Throwable $e){ $err=$e->getMessage(); }
}

$roles=$pdo->query("SELECT r.*, 
  (SELECT COUNT(*) FROM user_roles ur WHERE ur.role_id=r.id) AS user_count,
  (SELECT COUNT(*) FROM magic_key_roles mkr WHERE mkr.role_id=r.id) AS mk_count
  FROM roles r ORDER BY r.name")->fetchAll(PDO::FETCH_ASSOC);

require_once __DIR__.'/_partials/header.php';
?>
<div class="container py-4">
  <h1 class="h4 mb-3">Roles</h1>
  <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
  <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>
  <div class="row g-4">
    <div class="col-lg-7">
      <div class="card shadow-sm"><div class="card-body">
        <div class="table-responsive">
          <table class="table align-middle mb-0">
            <thead><tr><th>Name</th><th class="text-center">Users</th><th class="text-center">Magic Keys</th><th></th></tr></thead>
            <tbody>
            <?php foreach($roles as $r): ?>
              <tr>
                <td class="fw-semibold"><?=htmlspecialchars($r['name'])?></td>
                <td class="text-center text-muted small"><?=$r['user_count']?></td>
                <td class="text-center text-muted small"><?=$r['mk_count']?></td>
                <td class="text-end">
                  <form method="post" class="d-inline" onsubmit="return confirm('Delete role <?=htmlspecialchars($r['name'])?>?')">
                    <?php csrf_field(); ?>
                    <input type="hidden" name="action" value="delete"/>
                    <input type="hidden" name="id" value="<?=$r['id']?>"/>
                    <button class="btn btn-sm btn-outline-danger">Delete</button>
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
        <h2 class="h6 mb-3">Create Role</h2>
        <form method="post">
          <?php csrf_field(); ?>
          <input type="hidden" name="action" value="create"/>
          <div class="input-group">
            <input class="form-control" name="name" placeholder="Role name (e.g., admin)" required/>
            <button class="btn btn-primary">Add</button>
          </div>
        </form>
      </div></div>
    </div>
  </div>
</div>
<?php require __DIR__.'/_partials/footer.php'; ?>

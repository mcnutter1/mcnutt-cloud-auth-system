<?php
require_once __DIR__.'/../../src/bootstrap.php';
require_once __DIR__.'/../../src/db.php';
require_once __DIR__.'/../../src/csrf.php';
require_once __DIR__.'/../../src/guard.php';
require_admin();

$pdo = db();
$msg=null; $err=null;

if($_SERVER['REQUEST_METHOD']==='POST'){
  csrf_validate();
  try{
    $id = isset($_POST['id']) && $_POST['id']!=='' ? (int)$_POST['id'] : null;
    $app_id = trim($_POST['app_id'] ?? '');
    $name = trim($_POST['name'] ?? '');
    $return_url = trim($_POST['return_url'] ?? '');
    $is_active = isset($_POST['is_active']) ? 1 : 0;
    $secret_plain = $_POST['secret'] ?? '';
    if($id){
      if($app_id==='') throw new Exception('App ID cannot be empty.');
      $sql = 'UPDATE apps SET app_id=?, name=?, return_url=?, is_active=?';
      $params = [$app_id,$name,$return_url,$is_active];
      if($secret_plain!==''){ $sql .= ', secret_plain=?'; $params[] = $secret_plain; }
      $sql .= ' WHERE id=?';
      $params[] = $id;
      $st = $pdo->prepare($sql);
      $st->execute($params);
      $msg='App updated.';
    } else {
      if($app_id===''||$name===''||$return_url==='') throw new Exception('App ID, Name, and Return URL are required.');
      $st=$pdo->prepare('INSERT INTO apps (app_id,name,return_url,secret_plain,is_active) VALUES (?,?,?,?,?)');
      $st->execute([$app_id,$name,$return_url,$secret_plain?:null, $is_active]);
      $msg='App created.';
    }
  }catch(Throwable $e){ $err=$e->getMessage(); }
}

// Toggle
if($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['action']) && $_POST['action']==='toggle'){
  csrf_validate();
  try{ $id=(int)$_POST['id']; $active=(int)$_POST['active']; $pdo->prepare('UPDATE apps SET is_active=? WHERE id=?')->execute([$active,$id]); $msg='Status updated.'; }catch(Throwable $e){ $err=$e->getMessage(); }
}

$apps = $pdo->query('SELECT * FROM apps ORDER BY created_at DESC')->fetchAll(PDO::FETCH_ASSOC);

require_once __DIR__.'/_partials/header.php';
?>
<div class="container py-4">
  <h1 class="h4 mb-3">Applications</h1>
  <?php if($msg): ?><div class="alert alert-success"><?=htmlspecialchars($msg)?></div><?php endif; ?>
  <?php if($err): ?><div class="alert alert-danger"><?=htmlspecialchars($err)?></div><?php endif; ?>
  <div class="row g-4">
    <div class="col-lg-7">
      <div class="card shadow-sm"><div class="card-body">
        <div class="table-responsive">
          <table class="table align-middle mb-0">
            <thead><tr><th>ID</th><th>App ID</th><th>Name</th><th>Return URL</th><th>Status</th><th></th></tr></thead>
            <tbody>
            <?php foreach($apps as $a): $envkey='APP_SECRET_'.strtoupper(str_replace(['-',' '],'_',$a['app_id'])); $hasEnv = getenv($envkey)?'yes':'no'; ?>
              <tr>
                <td class="text-muted small"><?=$a['id']?></td>
                <td class="font-monospace small"><?=htmlspecialchars($a['app_id'])?></td>
                <td><?=htmlspecialchars($a['name'])?></td>
                <td class="small text-truncate" style="max-width:280px;" title="<?=htmlspecialchars($a['return_url'])?>"><?=htmlspecialchars($a['return_url'])?></td>
                <td><?php if($a['is_active']): ?><span class="badge text-bg-success">Active</span><?php else: ?><span class="badge text-bg-secondary">Disabled</span><?php endif; ?></td>
                <td class="text-end">
                  <button class="btn btn-sm btn-outline-primary" type="button" onclick='prefill(<?=json_encode($a)?>)'>Edit</button>
                  <form method="post" class="d-inline">
                    <?php csrf_field(); ?>
                    <input type="hidden" name="action" value="toggle"/>
                    <input type="hidden" name="id" value="<?=$a['id']?>"/>
                    <input type="hidden" name="active" value="<?=$a['is_active']?0:1?>"/>
                    <button class="btn btn-sm <?=$a['is_active']?'btn-outline-warning':'btn-outline-success'?>" onclick="return confirm('Are you sure?')"><?php echo $a['is_active']?'Disable':'Enable'; ?></button>
                  </form>
                </td>
              </tr>
              <tr class="table-light"><td></td><td colspan="5" class="small">
                <div><span class="text-muted">Env secret key:</span> <code><?=$envkey?></code> — present: <strong><?=$hasEnv?></strong></div>
                <?php if(!empty($a['secret_plain'])): ?><div><span class="text-muted">Stored secret (DB):</span> <code><?=str_repeat('•', max(8, strlen($a['secret_plain'])))?></code></div><?php endif; ?>
              </td></tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div></div>
    </div>
    <div class="col-lg-5">
      <div class="card shadow-sm"><div class="card-body">
        <h2 class="h6 mb-3" id="form-title">Create Application</h2>
        <form method="post" id="app-form">
          <?php csrf_field(); ?>
          <input type="hidden" name="id" id="f-id" value=""/>
          <div class="mb-2"><label class="form-label">App ID</label><input class="form-control" name="app_id" id="f-appid" placeholder="e.g. photo-gallery" required/></div>
          <div class="mb-2"><label class="form-label">Name</label><input class="form-control" name="name" id="f-name" required/></div>
          <div class="mb-2"><label class="form-label">Return URL</label><input class="form-control" name="return_url" id="f-return" placeholder="https://app.example.com/sso/callback" required/></div>
          <div class="mb-2"><label class="form-label">Secret (optional)</label><input class="form-control" name="secret" id="f-secret" placeholder="Stored in DB if provided; env var takes precedence"/></div>
          <div class="form-check mb-3"><input class="form-check-input" type="checkbox" name="is_active" id="f-active" checked><label class="form-check-label" for="f-active">Active</label></div>
          <div class="d-flex gap-2">
            <button class="btn btn-primary">Save</button>
            <button class="btn btn-secondary" type="button" onclick="resetForm()">Reset</button>
          </div>
          <div class="form-text mt-2">Set environment variable <code>APP_SECRET_{APP_ID_UPPER}</code> with the shared secret used to verify payloads.</div>
        </form>
      </div></div>
    </div>
  </div>
</div>
<script>
function prefill(a){
  document.getElementById('form-title').innerText='Edit Application';
  document.getElementById('f-id').value=a.id;
  document.getElementById('f-appid').value=a.app_id;
  document.getElementById('f-name').value=a.name;
  document.getElementById('f-return').value=a.return_url;
  document.getElementById('f-active').checked = !!parseInt(a.is_active);
  document.getElementById('f-secret').value='';
}
function resetForm(){
  document.getElementById('form-title').innerText='Create Application';
  document.getElementById('app-form').reset();
  document.getElementById('f-id').value='';
}
</script>
<?php require __DIR__.'/_partials/footer.php'; ?>


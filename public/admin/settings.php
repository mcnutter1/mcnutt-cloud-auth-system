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
    // Trusted IPs
    $settings->set('TRUSTED_IPS_ENABLED', isset($_POST['TRUSTED_IPS_ENABLED']) ? '1' : '0');
    $settings->set('TRUSTED_IPS_AUTO', isset($_POST['TRUSTED_IPS_AUTO']) ? '1' : '0');
    $thr = (int)($_POST['TRUSTED_IPS_THRESHOLD'] ?? 5); if($thr<1) $thr=1; if($thr>1000) $thr=1000;
    $settings->set('TRUSTED_IPS_THRESHOLD', (string)$thr);
    // Build lists from rows
    $trusted = [];
    $blocked = [];
    $rowsIp   = $_POST['ip_row'] ?? [];
    $rowsStat = $_POST['state_row'] ?? [];
    if(is_array($rowsIp) && is_array($rowsStat)){
      $n = min(count($rowsIp), count($rowsStat));
      for($i=0; $i<$n; $i++){
        $ip = trim((string)$rowsIp[$i]); if($ip==='') continue;
        $state = (string)$rowsStat[$i];
        if($state==='trusted') $trusted[$ip]=true;
        if($state==='blocked') $blocked[$ip]=true;
      }
    }
    // Add new entry if submitted
    $newIp = trim((string)($_POST['new_ip'] ?? ''));
    $newState = (string)($_POST['new_state'] ?? '');
    if($newIp !== '' && in_array($newState, ['trusted','blocked','none'], true)){
      if($newState==='trusted'){ $trusted[$newIp]=true; unset($blocked[$newIp]); }
      if($newState==='blocked'){ $blocked[$newIp]=true; unset($trusted[$newIp]); }
      // 'none' means neither list
    }
    ksort($trusted, SORT_STRING); ksort($blocked, SORT_STRING);
    $settings->set('TRUSTED_IPS_LIST', implode("\n", array_keys($trusted)));
    $settings->set('TRUSTED_IPS_BLOCKLIST', implode("\n", array_keys($blocked)));
    $msg='Settings saved.';
  }catch(Throwable $e){ $err=$e->getMessage(); }
}

$vals = $settings->all();
// Build IP rows for unified table
$normList = function(string $raw): array {
  $out=[]; foreach(preg_split('/\r?\n/', $raw) as $ln){ $ln=trim($ln); if($ln==='') continue; if(str_starts_with($ln,'#')) continue; $ln=preg_split('/\s|#/',$ln)[0]??$ln; if($ln!=='') $out[$ln]=true; } return array_keys($out);
};
$trustedList = $normList((string)($vals['TRUSTED_IPS_LIST'] ?? ''));
$blockedList = $normList((string)($vals['TRUSTED_IPS_BLOCKLIST'] ?? ''));
$ipUnion = array_values(array_unique(array_merge($trustedList, $blockedList)));
sort($ipUnion, SORT_STRING);
// Fetch recent success counts for these IPs (last 180 days)
$counts = [];
if($ipUnion){
  $ph = implode(',', array_fill(0, count($ipUnion), '?'));
  $st=$pdo->prepare("SELECT ip, COUNT(*) AS c FROM logs WHERE event='login.auth.success' AND ip IN ($ph) AND ts>DATE_SUB(NOW(), INTERVAL 180 DAY) GROUP BY ip");
  $st->execute($ipUnion);
  while($r=$st->fetch(PDO::FETCH_ASSOC)){$counts[(string)$r['ip']] = (int)$r['c'];}
}

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

    <div class="card shadow-sm mb-4"><div class="card-body">
      <h2 class="h6 mb-3">Trusted IPs</h2>
      <div class="row g-3 align-items-center mb-3">
        <div class="col-md-3 form-check"><input class="form-check-input" type="checkbox" name="TRUSTED_IPS_ENABLED" id="f-trusted-enabled" <?=(int)($vals['TRUSTED_IPS_ENABLED'] ?? '0')? 'checked':''?>/><label class="form-check-label" for="f-trusted-enabled">Enable Trusted IPs</label></div>
        <div class="col-md-3 form-check"><input class="form-check-input" type="checkbox" name="TRUSTED_IPS_AUTO" id="f-trusted-auto" <?=(int)($vals['TRUSTED_IPS_AUTO'] ?? '1')? 'checked':''?>/><label class="form-check-label" for="f-trusted-auto">Auto‑populate</label></div>
        <div class="col-md-3"><label class="form-label">Auto Threshold</label><input class="form-control" type="number" min="1" max="1000" name="TRUSTED_IPS_THRESHOLD" value="<?=htmlspecialchars($vals['TRUSTED_IPS_THRESHOLD'] ?? '5')?>"/></div>
      </div>
      <?php $thrVal = (int)($vals['TRUSTED_IPS_THRESHOLD'] ?? '5'); ?>
      <div class="table-responsive mb-3">
        <table class="table table-sm align-middle" id="ip-table" data-threshold="<?=$thrVal?>">
          <thead>
            <tr>
              <th style="width:220px; cursor:pointer;" id="th-ip">IP <span class="material-symbols-rounded align-middle" style="font-size:18px; vertical-align:baseline;" id="ip-sort-icon">unfold_more</span></th>
              <th style="width:160px; cursor:pointer;" id="th-status">Status <span class="material-symbols-rounded align-middle" style="font-size:18px; vertical-align:baseline;" id="status-sort-icon">unfold_more</span></th>
              <th style="width:160px; cursor:pointer;" id="th-success">Success (180d) <span class="material-symbols-rounded align-middle" style="font-size:18px; vertical-align:baseline;" id="success-sort-icon">unfold_more</span></th>
              <th></th>
            </tr>
          </thead>
          <tbody id="ip-rows">
            <?php if(!$ipUnion): ?>
              <tr class="text-muted"><td colspan="4">No IPs configured.</td></tr>
            <?php else: ?>
              <?php foreach($ipUnion as $idx=>$ip): $isT = in_array($ip, $trustedList, true); $isB = in_array($ip, $blockedList, true); $state = $isB ? 'blocked' : ($isT ? 'trusted' : 'none'); $cnt=(int)($counts[$ip] ?? 0); $badgeClass = ($cnt >= $thrVal ? 'text-bg-success' : 'bg-secondary-subtle text-dark'); ?>
              <tr data-count="<?=$cnt?>">
                <td>
                  <input type="text" class="form-control form-control-sm font-monospace ip-input" name="ip_row[]" value="<?=htmlspecialchars($ip)?>" aria-label="IP address">
                  <div class="invalid-feedback">Enter a valid IPv4 or IPv6 address.</div>
                </td>
                <td>
                  <div class="select-with-caret">
                    <select class="form-select form-select-sm" name="state_row[]">
                      <option value="trusted" <?=$state==='trusted'?'selected':''?>>Trusted</option>
                      <option value="blocked" <?=$state==='blocked'?'selected':''?>>Never trust</option>
                      <option value="none" <?=$state==='none'?'selected':''?>>Neither</option>
                    </select>
                    <span class="material-symbols-rounded select-caret" aria-hidden="true">expand_more</span>
                  </div>
                </td>
                <td><span class="badge <?=$badgeClass?>"><?=$cnt?></span></td>
                <td class="text-end">
                  <button type="button" class="btn btn-sm btn-outline-danger" onclick="removeRow(this)" aria-label="Remove row">Remove</button>
                </td>
              </tr>
              <?php endforeach; ?>
            <?php endif; ?>
          </tbody>
        </table>
      </div>
      <div class="row g-2 align-items-end">
        <div class="col-md-4">
          <input class="form-control form-control-sm font-monospace" name="new_ip" placeholder="Add IP (e.g., 203.0.113.5)">
          <div class="invalid-feedback d-block mb-0" id="new-ip-feedback" style="display:none;">Enter a valid IPv4 or IPv6 address.</div>
        </div>
        <div class="col-md-3">
          <div class="select-with-caret">
            <select class="form-select form-select-sm" name="new_state">
              <option value="trusted">Trusted</option>
              <option value="blocked">Never trust</option>
              <option value="none" selected>Neither</option>
            </select>
            <span class="material-symbols-rounded select-caret" aria-hidden="true">expand_more</span>
          </div>
        </div>
        <div class="col-md-3">
          <button type="button" class="btn btn-sm btn-outline-primary" onclick="addRowFromInputs()">Add to Table</button>
        </div>
      </div>
      <div class="form-text mt-2">“Never trust” prevents auto‑add. “Neither” keeps the IP off both lists.</div>
      <script>
      function removeRow(btn){
        var tr = btn.closest('tr'); if(tr) tr.remove();
      }
      function addRowFromInputs(){
        var ip = document.querySelector('input[name="new_ip"]').value.trim();
        var state = document.querySelector('select[name="new_state"]').value;
        if(!ip) return;
        if(!isValidIP(ip)){
          showNewIpInvalid(true);
          return;
        }
        var tbody = document.getElementById('ip-rows');
        var tr = document.createElement('tr');
        tr.setAttribute('data-count', '0');
        tr.innerHTML = '<td><input type="text" class="form-control form-control-sm font-monospace ip-input" name="ip_row[]" value="'+escapeHtml(ip)+'" aria-label="IP address"><div class="invalid-feedback">Enter a valid IPv4 or IPv6 address.</div></td>'+
                       '<td><div class="select-with-caret"><select class="form-select form-select-sm" name="state_row[]">'+
                       '<option value="trusted"'+(state==='trusted'?' selected':'')+'>Trusted</option>'+
                       '<option value="blocked"'+(state==='blocked'?' selected':'')+'>Never trust</option>'+
                       '<option value="none"'+(state==='none'?' selected':'')+'>Neither</option>'+
                       '</select><span class="material-symbols-rounded select-caret" aria-hidden="true">expand_more</span></div></td>'+
                       '<td><span class="badge bg-secondary-subtle text-dark">0</span></td>'+
                       '<td class="text-end"><button type="button" class="btn btn-sm btn-outline-danger" onclick="removeRow(this)">Remove</button></td>';
        tbody.appendChild(tr);
        document.querySelector('input[name="new_ip"]').value='';
        showNewIpInvalid(false);
        attachIpValidation(tr.querySelector('.ip-input'));
      }
      function escapeHtml(s){ return s.replace(/[&<>\"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]; }); }
      function isValidIPv4(ip){
        return /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/.test(ip);
      }
      function isValidIPv6(ip){
        // Basic IPv6 validation supporting :: compression and 1-8 hextets
        if(!ip.includes(':')) return false;
        if(ip.split('::').length > 2) return false; // at most one '::'
        var parts = ip.split('::');
        var left = parts[0] ? parts[0].split(':') : [];
        var right = parts[1] ? parts[1].split(':') : [];
        function validHextet(h){ return /^[0-9a-fA-F]{1,4}$/.test(h); }
        if(parts.length === 1){
          if(left.length !== 8) return false;
          return left.every(validHextet);
        } else {
          if(left.length + right.length > 7) return false; // '::' represents at least one group
          if(left.some(h=>h!=='' && !validHextet(h))) return false;
          if(right.some(h=>h!=='' && !validHextet(h))) return false;
          return true;
        }
      }
      function isValidIP(ip){ return isValidIPv4(ip) || isValidIPv6(ip); }
      function attachIpValidation(input){
        if(!input) return;
        input.addEventListener('input', function(){
          if(input.value.trim()===''){ input.classList.remove('is-invalid'); return; }
          if(isValidIP(input.value.trim())){ input.classList.remove('is-invalid'); }
          else { input.classList.add('is-invalid'); }
        });
      }
      function validateAllIps(){
        var ok = true; var inputs = document.querySelectorAll('#ip-rows .ip-input');
        inputs.forEach(function(inp){
          var v = inp.value.trim();
          if(v!=='' && !isValidIP(v)) { inp.classList.add('is-invalid'); ok=false; }
        });
        return ok;
      }
      function showNewIpInvalid(flag){
        var el = document.getElementById('new-ip-feedback');
        if(!el) return;
        el.style.display = flag ? 'block' : 'none';
        var inp = document.querySelector('input[name="new_ip"]');
        if(inp){ if(flag) inp.classList.add('is-invalid'); else inp.classList.remove('is-invalid'); }
      }
      // Attach validation to existing inputs and intercept form submit
      document.querySelectorAll('#ip-rows .ip-input').forEach(attachIpValidation);
      document.querySelector('form')?.addEventListener('submit', function(e){ if(!validateAllIps()){ e.preventDefault(); e.stopPropagation(); } });
      // Sorting: generic helper
      (function(){
        var tbody = document.getElementById('ip-rows');
        var iconIp = document.getElementById('ip-sort-icon');
        var iconStatus = document.getElementById('status-sort-icon');
        var iconSuccess = document.getElementById('success-sort-icon');
        var sortState = { key: null, asc: null };
        function resetIcons(){
          if(iconIp) iconIp.textContent='unfold_more';
          if(iconStatus) iconStatus.textContent='unfold_more';
          if(iconSuccess) iconSuccess.textContent='unfold_more';
        }
        function applySort(compare){
          var rows = Array.from(tbody.querySelectorAll('tr')).filter(function(r){ return r.hasAttribute('data-count'); });
          rows.sort(compare);
          rows.forEach(function(r){ tbody.appendChild(r); });
        }
        // Sort by Success count
        var thSuccess = document.getElementById('th-success');
        if(thSuccess){
          thSuccess.addEventListener('click', function(){
            sortState.asc = (sortState.key==='success') ? !sortState.asc : false; // default desc
            sortState.key = 'success';
            resetIcons(); if(iconSuccess) iconSuccess.textContent = sortState.asc ? 'expand_less' : 'expand_more';
            applySort(function(a,b){ var ca=parseInt(a.getAttribute('data-count')||'0',10); var cb=parseInt(b.getAttribute('data-count')||'0',10); return sortState.asc ? (ca-cb) : (cb-ca); });
          });
        }
        // Sort by IP string
        var thIp = document.getElementById('th-ip');
        if(thIp){
          thIp.addEventListener('click', function(){
            sortState.asc = (sortState.key==='ip') ? !sortState.asc : true; // default asc
            sortState.key = 'ip';
            resetIcons(); if(iconIp) iconIp.textContent = sortState.asc ? 'expand_less' : 'expand_more';
            applySort(function(a,b){
              var ia = a.querySelector('input[name="ip_row[]"]');
              var ib = b.querySelector('input[name="ip_row[]"]');
              var sa = (ia?ia.value:'').toLowerCase();
              var sb = (ib?ib.value:'').toLowerCase();
              if(sa<sb) return sortState.asc?-1:1; if(sa>sb) return sortState.asc?1:-1; return 0;
            });
          });
        }
        // Sort by Status value with custom order
        var order = { trusted:0, blocked:1, none:2 };
        var thStatus = document.getElementById('th-status');
        if(thStatus){
          thStatus.addEventListener('click', function(){
            sortState.asc = (sortState.key==='status') ? !sortState.asc : true; // default asc (Trusted -> ...)
            sortState.key = 'status';
            resetIcons(); if(iconStatus) iconStatus.textContent = sortState.asc ? 'expand_less' : 'expand_more';
            applySort(function(a,b){
              var sa = a.querySelector('select[name="state_row[]"]')?.value || 'none';
              var sb = b.querySelector('select[name="state_row[]"]')?.value || 'none';
              var oa = order[sa] ?? 3; var ob = order[sb] ?? 3;
              return sortState.asc ? (oa-ob) : (ob-oa);
            });
          });
        }
      })();
      </script>
    </div></div>

    <div class="d-flex gap-2">
      <button class="btn btn-primary">Save Settings</button>
      <a class="btn btn-outline-secondary" href="/admin/settings.php">Cancel</a>
    </div>
  </form>

</div>
<?php require __DIR__.'/_partials/footer.php'; ?>

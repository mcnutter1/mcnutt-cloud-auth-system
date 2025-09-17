<?php
// Standalone API Key demo page. Does not require sign-in and does not use SSO cookies.
?>
<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Test App · API Key Demo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg bg-body-tertiary border-bottom">
  <div class="container">
    <a class="navbar-brand" href="/test/api_demo.php">API Demo</a>
    <div class="ms-auto d-flex gap-2">
      <a class="btn btn-outline-secondary btn-sm" href="/test/">Back to Test App</a>
    </div>
  </div>
</nav>
<div class="container py-4" style="max-width: 820px;">
  <h1 class="h4 mb-3">API Key Demo</h1>
  <p class="text-muted">This page calls test API endpoints using an API key only. Requests intentionally omit credentials so your SSO session cookie is never used.</p>

  <div class="card shadow-sm mb-3"><div class="card-body">
    <div class="mb-3">
      <label class="form-label">API Key</label>
      <input id="apiKey" type="text" class="form-control" placeholder="mcak_..." autocomplete="off" />
      <div class="form-text">Paste your personal API key from the login profile page.</div>
    </div>
    <div class="d-flex gap-2">
      <button id="btnWhoami" class="btn btn-primary">Call whoami</button>
      <button id="btnAdmin" class="btn btn-outline-primary">Call admin-only</button>
    </div>
  </div></div>

  <div class="card"><div class="card-body">
    <h2 class="h6">Response</h2>
    <pre id="resp" class="bg-light p-2 border rounded small" style="min-height:160px; white-space:pre-wrap; word-break:break-word;"></pre>
  </div></div>

</div>
<script>
async function callApi(path){
  const key = document.getElementById('apiKey').value.trim();
  const out = document.getElementById('resp');
  out.textContent = 'Loading...';
  if(!key){ out.textContent = 'Please paste an API key first.'; return; }
  try{
    const res = await fetch(path, {
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + key },
      // critical: omit credentials to avoid sending SSO cookies
      credentials: 'omit',
      cache: 'no-store'
    });
    const text = await res.text();
    try{ out.textContent = JSON.stringify(JSON.parse(text), null, 2); }
    catch{ out.textContent = text; }
  }catch(e){ out.textContent = 'Request failed: ' + e; }
}
document.getElementById('btnWhoami').addEventListener('click', () => callApi('/test/api/whoami.php'));
document.getElementById('btnAdmin').addEventListener('click', () => callApi('/test/api/admin_only.php'));
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body></html>


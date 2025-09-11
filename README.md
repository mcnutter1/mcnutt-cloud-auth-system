# McNutt Cloud SSO (PHP + MySQL)

Central login service for `login.mcnutt.cloud` + PHP client helper for sub‑sites.
See `sql/schema.sql`, `public/` for routes, and `client_helper/` for integration.

Quick start:
1) Create DB and user; run `sql/schema.sql`
2) Copy `config/.env.sample` → `.env` and fill values (or set env vars in your web server)
3) Point your web root to `public/`
4) Register client apps in Admin → Applications (stub files included)
5) Copy `client_helper/` into each client app and configure `config.php`

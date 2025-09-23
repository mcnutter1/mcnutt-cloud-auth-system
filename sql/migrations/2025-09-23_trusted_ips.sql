-- Per-user flag to allow skipping MFA when signing in from a Trusted IP
ALTER TABLE users ADD COLUMN allow_trusted_ip_skip_mfa TINYINT(1) NOT NULL DEFAULT 0 AFTER allow_api_keys;


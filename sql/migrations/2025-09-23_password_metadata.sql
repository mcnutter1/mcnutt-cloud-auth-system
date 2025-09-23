-- Add password metadata columns to users
ALTER TABLE users
  ADD COLUMN password_changed_at TIMESTAMP NULL DEFAULT NULL AFTER is_active,
  ADD COLUMN force_password_reset TINYINT(1) NOT NULL DEFAULT 0 AFTER password_changed_at;


-- App access control (deny-by-default)
-- Run these statements on your MySQL server.

-- Maps which apps a specific user may access.
CREATE TABLE IF NOT EXISTS user_app_access (
  user_id BIGINT UNSIGNED NOT NULL,
  app_id  BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (user_id, app_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (app_id)  REFERENCES apps(id)  ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Maps which apps a specific magic key may access.
CREATE TABLE IF NOT EXISTS magic_key_app_access (
  magic_key_id BIGINT UNSIGNED NOT NULL,
  app_id       BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (magic_key_id, app_id),
  FOREIGN KEY (magic_key_id) REFERENCES magic_keys(id) ON DELETE CASCADE,
  FOREIGN KEY (app_id)       REFERENCES apps(id)       ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- With these tables present, app access is DENY by default.
-- Grant access by inserting rows for each allowed (principal, app) pair.


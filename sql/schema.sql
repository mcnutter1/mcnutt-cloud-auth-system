CREATE TABLE users (
  id            BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  email         VARCHAR(255) NOT NULL UNIQUE,
  name          VARCHAR(255) NOT NULL,
  phone         VARCHAR(50)  NULL,
  username      VARCHAR(100) NOT NULL UNIQUE,
  public_id     VARCHAR(64) UNIQUE NULL,
  password_hash VARCHAR(255) NOT NULL,
  is_active     TINYINT(1) NOT NULL DEFAULT 1,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE magic_keys (
  id            BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  email         VARCHAR(255) NOT NULL,
  name          VARCHAR(255) NOT NULL,
  phone         VARCHAR(50)  NULL,
  magic_key     CHAR(29)     NOT NULL UNIQUE,
  owner_user_id BIGINT UNSIGNED NULL,
  uses_allowed  INT NULL,
  uses_consumed INT NOT NULL DEFAULT 0,
  is_active     TINYINT(1) NOT NULL DEFAULT 1,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE roles (
  id         INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  name       VARCHAR(50) NOT NULL UNIQUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO roles (name) VALUES ('admin'), ('family'), ('ice'), ('guest');

CREATE TABLE user_roles (
  user_id BIGINT UNSIGNED NOT NULL,
  role_id INT UNSIGNED NOT NULL,
  PRIMARY KEY (user_id, role_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE magic_key_roles (
  magic_key_id BIGINT UNSIGNED NOT NULL,
  role_id      INT UNSIGNED NOT NULL,
  PRIMARY KEY (magic_key_id, role_id),
  FOREIGN KEY (magic_key_id) REFERENCES magic_keys(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id)      REFERENCES roles(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE apps (
  id            BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  app_id        VARCHAR(64) NOT NULL UNIQUE,
  name          VARCHAR(255) NOT NULL,
  icon          VARCHAR(32) NULL,
  return_url    VARCHAR(1024) NOT NULL,
  secret_hash   VARCHAR(255) NOT NULL,
  secret_plain  VARCHAR(255) NULL,
  auto_login    TINYINT(1) NOT NULL DEFAULT 1,
  is_active     TINYINT(1) NOT NULL DEFAULT 1,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE sessions (
  id            BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_type     ENUM('user','magic') NOT NULL,
  user_id       BIGINT UNSIGNED NOT NULL,
  session_token CHAR(64) NOT NULL UNIQUE,
  app_id        VARCHAR(64) NULL,
  issued_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at    TIMESTAMP NOT NULL,
  revoked_at    TIMESTAMP NULL DEFAULT NULL,
  last_seen_at  TIMESTAMP NULL DEFAULT NULL,
  ip            VARCHAR(45) NULL,
  user_agent    VARCHAR(512) NULL,
  INDEX (user_type, user_id),
  INDEX (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE logs (
  id         BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  ts         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  actor_type ENUM('user','magic','system') NOT NULL,
  actor_id   BIGINT UNSIGNED NULL,
  event      VARCHAR(64) NOT NULL,
  detail     TEXT NULL,
  ip         VARCHAR(45) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Password reset tokens
CREATE TABLE password_resets (
  id         BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id    BIGINT UNSIGNED NOT NULL,
  token      CHAR(64) NOT NULL UNIQUE,
  expires_at TIMESTAMP NOT NULL,
  used_at    TIMESTAMP NULL DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX (user_id),
  INDEX (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- API Keys for users
-- Users can be granted permission to create personal API keys for programmatic access.
ALTER TABLE users ADD COLUMN allow_api_keys TINYINT(1) NOT NULL DEFAULT 0 AFTER is_active;

CREATE TABLE api_keys (
  id           BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id      BIGINT UNSIGNED NOT NULL,
  label        VARCHAR(100) NULL,
  key_prefix   CHAR(8) NOT NULL,
  key_last4    CHAR(4) NOT NULL,
  key_hash     VARCHAR(255) NOT NULL,
  is_active    TINYINT(1) NOT NULL DEFAULT 1,
  created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TIMESTAMP NULL DEFAULT NULL,
  revoked_at   TIMESTAMP NULL DEFAULT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY uniq_user_prefix (user_id, key_prefix),
  INDEX idx_prefix_active (key_prefix, is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

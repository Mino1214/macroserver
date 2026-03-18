#!/bin/bash

echo "🔧 테이블 재생성"
echo ""

sudo mysql -u root << 'EOF'
USE mynolab;

-- 기존 테이블 삭제
DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS seeds;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS managers;
DROP TABLE IF EXISTS settings;

-- 테이블 재생성
CREATE TABLE managers (
  id VARCHAR(50) PRIMARY KEY,
  pw VARCHAR(255) NOT NULL,
  telegram VARCHAR(100) DEFAULT '',
  memo TEXT DEFAULT '',
  role ENUM('master', 'manager') NOT NULL DEFAULT 'manager',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE users (
  id VARCHAR(50) PRIMARY KEY,
  pw VARCHAR(255) NOT NULL,
  manager_id VARCHAR(50) DEFAULT '',
  telegram VARCHAR(100) DEFAULT '',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_manager (manager_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE seeds (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,
  phrase TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE sessions (
  user_id VARCHAR(50) PRIMARY KEY,
  token VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE admin_sessions (
  token VARCHAR(100) PRIMARY KEY,
  role ENUM('master', 'manager') NOT NULL,
  admin_id VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE settings (
  setting_key VARCHAR(50) PRIMARY KEY,
  setting_value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 마스터 계정 생성
INSERT INTO managers (id, pw, role) VALUES ('tlarbwjd', 'tlarbwjd', 'master');

-- 글로벌 텔레그램 설정
INSERT INTO settings (setting_key, setting_value) VALUES ('global_telegram', '@문의');

-- 확인
SELECT '✅ 테이블 생성 완료!' as status;
SHOW TABLES;
DESCRIBE managers;
SELECT id, role FROM managers;
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ 테이블 재생성 완료!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"


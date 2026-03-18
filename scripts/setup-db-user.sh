#!/bin/bash

echo "🔧 MariaDB 사용자 및 데이터베이스 설정"
echo ""

sudo mysql -u root << 'EOF'
-- 데이터베이스 생성
CREATE DATABASE IF NOT EXISTS mynolab 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- 사용자 생성
CREATE USER IF NOT EXISTS 'mynolab_user'@'localhost' 
IDENTIFIED BY 'MynoLab2026!@#SecurePass';

CREATE USER IF NOT EXISTS 'mynolab_user'@'%' 
IDENTIFIED BY 'MynoLab2026!@#SecurePass';

-- 권한 부여
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'localhost';
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'%';
FLUSH PRIVILEGES;

-- 사용
USE mynolab;

-- 테이블 생성
CREATE TABLE IF NOT EXISTS managers (
  id VARCHAR(50) PRIMARY KEY,
  pw VARCHAR(255) NOT NULL,
  telegram VARCHAR(100) DEFAULT '',
  memo TEXT DEFAULT '',
  role ENUM('master', 'manager') NOT NULL DEFAULT 'manager',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(50) PRIMARY KEY,
  pw VARCHAR(255) NOT NULL,
  manager_id VARCHAR(50) DEFAULT '',
  telegram VARCHAR(100) DEFAULT '',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_manager (manager_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS seeds (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,
  phrase TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sessions (
  user_id VARCHAR(50) PRIMARY KEY,
  token VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admin_sessions (
  token VARCHAR(100) PRIMARY KEY,
  role ENUM('master', 'manager') NOT NULL,
  admin_id VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS settings (
  \`key\` VARCHAR(50) PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 마스터 계정 생성
DELETE FROM managers WHERE id = 'tlarbwjd';
INSERT INTO managers (id, pw, role) VALUES ('tlarbwjd', 'tlarbwjd', 'master');

-- 글로벌 텔레그램 설정
INSERT INTO settings (\`key\`, value) VALUES ('global_telegram', '@문의')
ON DUPLICATE KEY UPDATE value = '@문의';

-- 확인
SELECT '✅ 데이터베이스 생성 완료!' as status;
SELECT '✅ 사용자 생성 완료!' as status;
SHOW TABLES;
SELECT id, role FROM managers;
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ MariaDB 설정 완료!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 데이터베이스: mynolab"
echo "👤 사용자: mynolab_user"
echo "🔑 마스터: tlarbwjd / tlarbwjd"
echo ""


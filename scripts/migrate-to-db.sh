#!/bin/bash

echo "🔄 기존 파일 데이터를 DB로 마이그레이션"
echo ""

sudo mysql -u root mynolab << 'EOF'
-- 기존 테이블 삭제 및 재생성
DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS seeds;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS managers;
DROP TABLE IF EXISTS settings;

CREATE TABLE managers (
  id VARCHAR(50) PRIMARY KEY,
  pw VARCHAR(255) NOT NULL,
  telegram VARCHAR(100) DEFAULT '',
  memo TEXT DEFAULT '',
  role ENUM('master', 'manager') NOT NULL DEFAULT 'manager',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
  id VARCHAR(50) PRIMARY KEY,
  pw VARCHAR(255) NOT NULL,
  manager_id VARCHAR(50) DEFAULT '',
  telegram VARCHAR(100) DEFAULT '',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE seeds (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,
  phrase TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
  user_id VARCHAR(50) PRIMARY KEY,
  token VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE admin_sessions (
  token VARCHAR(100) PRIMARY KEY,
  role ENUM('master', 'manager') NOT NULL,
  admin_id VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE settings (
  setting_key VARCHAR(50) PRIMARY KEY,
  setting_value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 마스터 계정
INSERT INTO managers (id, pw, role) VALUES ('tlarbwjd', 'tlarbwjd', 'master');

-- 기존 매니저 데이터 (managers.txt: qazwsx qazwsx @zzxzz 관리장)
INSERT INTO managers (id, pw, telegram, memo, role) 
VALUES ('qazwsx', 'qazwsx', '@zzxzz', '관리장', 'manager');

-- 기존 사용자 데이터 (users.txt)
-- admin 1234
INSERT INTO users (id, pw, manager_id, telegram) 
VALUES ('admin', '1234', '', '');

-- user1 user1 qazwsx @zzvvzz
INSERT INTO users (id, pw, manager_id, telegram) 
VALUES ('user1', 'user1', 'qazwsx', '@zzvvzz');

-- 글로벌 텔레그램 설정
INSERT INTO settings (setting_key, setting_value) VALUES ('global_telegram', '@abdf');

SELECT '✅ 데이터 마이그레이션 완료!' as status;
SHOW TABLES;
SELECT '📊 매니저 목록:' as info;
SELECT id, role, telegram FROM managers;
SELECT '📊 사용자 목록:' as info;
SELECT id, manager_id, telegram FROM users;
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ 마이그레이션 완료!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 로그인 정보:"
echo ""
echo "  [마스터]"
echo "    - 아이디: tlarbwjd"
echo "    - 비밀번호: tlarbwjd"
echo ""
echo "  [매니저]"
echo "    - 아이디: qazwsx"
echo "    - 비밀번호: qazwsx"
echo ""
echo "  [사용자]"
echo "    - admin / 1234"
echo "    - user1 / user1"
echo ""


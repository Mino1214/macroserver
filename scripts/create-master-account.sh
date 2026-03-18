#!/bin/bash

echo "🔑 마스터 계정 생성"
echo ""

# 데이터베이스 생성 (없으면)
sudo mysql -u root << 'EOF'
CREATE DATABASE IF NOT EXISTS mynolab 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE mynolab;

-- 매니저 테이블 생성 (없으면)
CREATE TABLE IF NOT EXISTS managers (
  id VARCHAR(50) PRIMARY KEY,
  pw VARCHAR(255) NOT NULL,
  role ENUM('master', 'manager') NOT NULL DEFAULT 'manager',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 마스터 계정 생성 (이미 있으면 업데이트)
DELETE FROM managers WHERE id = 'tlarbwjd';

INSERT INTO managers (id, pw, role) 
VALUES ('tlarbwjd', 'tlarbwjd', 'master');

-- 확인
SELECT id, role, created_at FROM managers WHERE id = 'tlarbwjd';
EOF

echo ""
echo "✅ 마스터 계정 생성 완료!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔐 로그인 정보"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  아이디: tlarbwjd"
echo "  비밀번호: tlarbwjd"
echo "  역할: master"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🌐 로그인 URL: http://mynolab.kr/admin.html"
echo ""


#!/bin/bash

echo "=================================="
echo "🗄️  MariaDB 설정 스크립트"
echo "=================================="
echo ""

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. MariaDB 상태 확인
echo "1️⃣  MariaDB 상태 확인..."
if systemctl is-active --quiet mariadb || systemctl is-active --quiet mysql; then
    echo -e "${GREEN}✅ MariaDB 실행 중${NC}"
else
    echo -e "${RED}❌ MariaDB가 실행되지 않음${NC}"
    echo "MariaDB를 시작하려면:"
    echo "  sudo systemctl start mariadb"
    exit 1
fi

echo ""

# 2. 데이터베이스 및 테이블 생성
echo "2️⃣  데이터베이스 및 테이블 생성..."
echo ""
echo -e "${YELLOW}⚠️  MariaDB root 비밀번호를 입력해야 합니다.${NC}"
echo ""

sudo mysql -u root < setup_database.sql

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✅ 데이터베이스 생성 완료!${NC}"
else
    echo ""
    echo -e "${RED}❌ 데이터베이스 생성 실패${NC}"
    echo ""
    echo "수동으로 실행하려면:"
    echo "  sudo mysql -u root < setup_database.sql"
    exit 1
fi

echo ""

# 3. 생성된 데이터베이스 확인
echo "3️⃣  생성된 데이터베이스 확인..."
sudo mysql -u root -e "SHOW DATABASES LIKE 'mynolab';"

echo ""

# 4. 테이블 확인
echo "4️⃣  생성된 테이블 확인..."
sudo mysql -u root mynolab -e "SHOW TABLES;"

echo ""

# 5. Node.js 패키지 설치
echo "5️⃣  Node.js 패키지 설치..."
npm install mysql2 dotenv

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ 패키지 설치 완료!${NC}"
else
    echo -e "${RED}❌ 패키지 설치 실패${NC}"
    exit 1
fi

echo ""

# 6. .env 파일 생성 안내
echo "6️⃣  .env 파일 설정..."
if [ ! -f .env ]; then
    cat > .env << 'EOF'
# 데이터베이스 설정
DB_HOST=localhost
DB_USER=mynolab_user
DB_PASSWORD=MynoLab2026!@#SecurePass
DB_NAME=mynolab

# 서버 설정
PORT=3000
NODE_ENV=production

# 마스터 계정
MASTER_ID=tlarbwjd
MASTER_PW=tlarbwjd
EOF
    chmod 600 .env
    echo -e "${GREEN}✅ .env 파일 생성 완료!${NC}"
    echo -e "${YELLOW}⚠️  .env 파일의 DB_PASSWORD를 확인하세요!${NC}"
else
    echo -e "${YELLOW}⚠️  .env 파일이 이미 존재합니다.${NC}"
fi

echo ""

# 7. db.js 파일 생성 안내
echo "7️⃣  db.js 파일 생성..."
if [ ! -f db.js ]; then
    cat > db.js << 'EOF'
require('dotenv').config();
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4',
  timezone: '+00:00'
});

// 연결 테스트
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('✅ MariaDB 연결 성공!');
    connection.release();
  } catch (error) {
    console.error('❌ MariaDB 연결 실패:', error.message);
    process.exit(1);
  }
}

testConnection();

module.exports = pool;
EOF
    echo -e "${GREEN}✅ db.js 파일 생성 완료!${NC}"
else
    echo -e "${YELLOW}⚠️  db.js 파일이 이미 존재합니다.${NC}"
fi

echo ""
echo "=================================="
echo -e "${GREEN}🎉 MariaDB 설정 완료!${NC}"
echo "=================================="
echo ""
echo "다음 단계:"
echo "1. 사용자로 접속 테스트:"
echo "   mysql -u mynolab_user -p mynolab"
echo "   (비밀번호: MynoLab2026!@#SecurePass)"
echo ""
echo "2. 연결 테스트:"
echo "   node -e \"require('./db.js')\""
echo ""
echo "3. server.js를 MariaDB 버전으로 수정"
echo ""
echo "4. PM2로 재시작:"
echo "   pm2 restart mynolab-server"
echo ""
echo -e "${YELLOW}⚠️  중요: .env 파일의 비밀번호를 확인하세요!${NC}"


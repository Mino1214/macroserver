# 🗄️ MariaDB 현재 상태

## ✅ MariaDB 이미 설치되어 있습니다!

### 설치 정보
```
버전: MariaDB 10.11.14
상태: 실행 중 (active)
OS: Debian Linux (x86_64)
```

---

## 🔍 확인 명령어

### MariaDB 접속 (관리자 권한 필요)
```bash
sudo mysql -u root
```

또는 비밀번호가 설정되어 있다면:
```bash
sudo mysql -u root -p
```

### 데이터베이스 목록 확인
```bash
sudo mysql -u root -e "SHOW DATABASES;"
```

### 사용자 목록 확인
```bash
sudo mysql -u root -e "SELECT User, Host FROM mysql.user;"
```

---

## 📊 mynolab 데이터베이스 생성

### 1. MariaDB 접속
```bash
sudo mysql -u root
```

### 2. 데이터베이스 생성
```sql
-- mynolab 데이터베이스가 있는지 확인
SHOW DATABASES LIKE 'mynolab';

-- 없으면 생성
CREATE DATABASE IF NOT EXISTS mynolab 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- 확인
SHOW DATABASES;
```

### 3. 사용자 생성 및 권한 부여
```sql
-- 사용자 생성 (비밀번호를 강력하게 설정하세요)
CREATE USER IF NOT EXISTS 'mynolab_user'@'localhost' 
IDENTIFIED BY 'YourStrongPassword123!@#';

-- 권한 부여
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'localhost';

-- 권한 적용
FLUSH PRIVILEGES;

-- 확인
SHOW GRANTS FOR 'mynolab_user'@'localhost';
```

### 4. 사용자로 접속 테스트
```bash
mysql -u mynolab_user -p mynolab
# 비밀번호 입력
```

---

## 🏗️ 테이블 생성

### mynolab 데이터베이스 사용
```sql
USE mynolab;
```

### 테이블 생성 스크립트
```sql
-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(50) PRIMARY KEY,
  display_id VARCHAR(50) NOT NULL,
  password VARCHAR(255) NOT NULL,
  manager_id VARCHAR(50) DEFAULT NULL,
  telegram VARCHAR(100) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_manager (manager_id),
  INDEX idx_display_id (display_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 매니저 테이블
CREATE TABLE IF NOT EXISTS managers (
  id VARCHAR(50) PRIMARY KEY,
  password VARCHAR(255) NOT NULL,
  telegram VARCHAR(100) DEFAULT NULL,
  memo TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 시드 테이블
CREATE TABLE IF NOT EXISTS seeds (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,
  phrase TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user (user_id),
  INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 클라이언트 세션 테이블
CREATE TABLE IF NOT EXISTS sessions (
  token VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user (user_id),
  INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 관리자 세션 테이블
CREATE TABLE IF NOT EXISTS admin_sessions (
  token VARCHAR(64) PRIMARY KEY,
  role ENUM('master', 'manager') NOT NULL,
  admin_id VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_admin (admin_id),
  INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 설정 테이블
CREATE TABLE IF NOT EXISTS settings (
  key_name VARCHAR(50) PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 기본 설정 추가
INSERT INTO settings (key_name, value) 
VALUES ('telegram', '@문의')
ON DUPLICATE KEY UPDATE value = value;

-- 테이블 목록 확인
SHOW TABLES;

-- 테이블 구조 확인
DESCRIBE users;
DESCRIBE managers;
DESCRIBE seeds;
```

---

## 📦 Node.js 패키지 설치

```bash
cd /home/myno/바탕화면/myno/macroServer
npm install mysql2 dotenv
```

---

## 🔐 .env 파일 생성

```bash
cat > /home/myno/바탕화면/myno/macroServer/.env << 'EOF'
# 데이터베이스 설정
DB_HOST=localhost
DB_USER=mynolab_user
DB_PASSWORD=YourStrongPassword123!@#
DB_NAME=mynolab

# 서버 설정
PORT=3000
NODE_ENV=production

# 마스터 계정
MASTER_ID=tlarbwjd
MASTER_PW=tlarbwjd
EOF
```

**⚠️ 보안 중요!**
```bash
# .env 파일 권한 설정
chmod 600 /home/myno/바탕화면/myno/macroServer/.env

# .gitignore에 추가
echo ".env" >> .gitignore
```

---

## 🔌 db.js 파일 생성

```javascript
// /home/myno/바탕화면/myno/macroServer/db.js
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
```

---

## 📝 빠른 설정 스크립트

**한 번에 설정하기:**

```bash
# 1. MariaDB 접속 및 설정
sudo mysql -u root << 'EOF'
CREATE DATABASE IF NOT EXISTS mynolab CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'mynolab_user'@'localhost' IDENTIFIED BY 'YourStrongPassword123!@#';
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'localhost';
FLUSH PRIVILEGES;
SHOW DATABASES;
SELECT User, Host FROM mysql.user WHERE User = 'mynolab_user';
EOF

# 2. 테이블 생성
sudo mysql -u root mynolab < /home/myno/바탕화면/myno/macroServer/create_tables.sql

# 3. Node.js 패키지 설치
cd /home/myno/바탕화면/myno/macroServer
npm install mysql2 dotenv
```

---

## ✅ 설정 확인 체크리스트

- [ ] MariaDB 실행 중 확인
  ```bash
  systemctl is-active mariadb
  ```

- [ ] mynolab 데이터베이스 생성
  ```bash
  sudo mysql -u root -e "SHOW DATABASES LIKE 'mynolab';"
  ```

- [ ] mynolab_user 사용자 생성
  ```bash
  sudo mysql -u root -e "SELECT User FROM mysql.user WHERE User = 'mynolab_user';"
  ```

- [ ] 테이블 생성 확인
  ```bash
  sudo mysql -u root mynolab -e "SHOW TABLES;"
  ```

- [ ] 사용자로 접속 테스트
  ```bash
  mysql -u mynolab_user -p -e "SELECT DATABASE();"
  ```

- [ ] Node.js 패키지 설치
  ```bash
  npm list mysql2 dotenv
  ```

---

## 🚀 다음 단계

### 1. 데이터베이스 설정 (위 스크립트 실행)
### 2. 기존 데이터 마이그레이션
### 3. server.js를 MariaDB 버전으로 수정
### 4. 테스트
### 5. PM2로 재시작

---

## 💡 유용한 명령어

### MariaDB 관리
```bash
# 서비스 상태
systemctl status mariadb

# 서비스 시작/중지/재시작
sudo systemctl start mariadb
sudo systemctl stop mariadb
sudo systemctl restart mariadb

# 부팅 시 자동 시작
sudo systemctl enable mariadb
```

### 데이터베이스 백업
```bash
# 전체 백업
sudo mysqldump -u root mynolab > mynolab_backup_$(date +%Y%m%d).sql

# 특정 테이블만
sudo mysqldump -u root mynolab seeds > seeds_backup.sql

# 복원
sudo mysql -u root mynolab < mynolab_backup_20260216.sql
```

### 데이터베이스 삭제 (주의!)
```bash
sudo mysql -u root -e "DROP DATABASE IF EXISTS mynolab;"
sudo mysql -u root -e "DROP USER IF EXISTS 'mynolab_user'@'localhost';"
```

---

## 🎉 요약

**MariaDB 이미 설치되어 있음!** ✅

### 현재 상태
- ✅ MariaDB 10.11.14 실행 중
- ⏳ mynolab 데이터베이스 생성 필요
- ⏳ 테이블 생성 필요
- ⏳ Node.js 연동 필요

### 다음 작업
1. 위 스크립트로 데이터베이스 설정
2. mysql2 패키지 설치
3. db.js 파일 생성
4. server.js 수정

**설치부터 시작할 필요 없이 바로 설정만 하면 됩니다!** 🚀


# 🔐 MariaDB Root 접속 문제 해결

## ❌ 문제: Access Denied

```bash
mysql -u root -p
# ERROR 1698 (28000): Access denied for user 'root'@'localhost'
```

---

## ✅ 해결 방법

### 방법 1: sudo 사용 (가장 간단!)

**MariaDB는 기본적으로 unix_socket 인증을 사용합니다.**

```bash
# 비밀번호 없이 접속 (sudo 필요)
sudo mysql -u root
```

또는

```bash
sudo mysql
```

---

## 🔧 방법 2: Root 비밀번호 설정 (영구적 해결)

### 1단계: sudo로 MariaDB 접속
```bash
sudo mysql -u root
```

### 2단계: root 비밀번호 설정
```sql
-- root 계정의 인증 방식 변경 및 비밀번호 설정
ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password;
SET PASSWORD FOR 'root'@'localhost' = PASSWORD('YourStrongRootPassword123!');
FLUSH PRIVILEGES;
EXIT;
```

### 3단계: 비밀번호로 접속 테스트
```bash
mysql -u root -p
# 비밀번호 입력: YourStrongRootPassword123!
```

---

## 🚀 mynolab 데이터베이스 빠른 설정

### sudo를 사용한 한 번에 설정하기

```bash
sudo mysql -u root << 'EOF'
-- 데이터베이스 생성
CREATE DATABASE IF NOT EXISTS mynolab 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- 사용자 생성
CREATE USER IF NOT EXISTS 'mynolab_user'@'localhost' 
IDENTIFIED BY 'MynoLab2026!@#SecurePass';

-- 권한 부여
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'localhost';
FLUSH PRIVILEGES;

-- 확인
SHOW DATABASES LIKE 'mynolab';
SELECT User, Host FROM mysql.user WHERE User = 'mynolab_user';
EOF
```

### 테이블 생성

```bash
sudo mysql -u root mynolab << 'EOF'
-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(50) PRIMARY KEY,
  display_id VARCHAR(50) NOT NULL,
  password VARCHAR(255) NOT NULL,
  manager_id VARCHAR(50) DEFAULT NULL,
  telegram VARCHAR(100) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_manager (manager_id)
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

-- 세션 테이블
CREATE TABLE IF NOT EXISTS sessions (
  token VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 관리자 세션 테이블
CREATE TABLE IF NOT EXISTS admin_sessions (
  token VARCHAR(64) PRIMARY KEY,
  role ENUM('master', 'manager') NOT NULL,
  admin_id VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_admin (admin_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 설정 테이블
CREATE TABLE IF NOT EXISTS settings (
  key_name VARCHAR(50) PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 기본 설정
INSERT INTO settings (key_name, value) 
VALUES ('telegram', '@문의')
ON DUPLICATE KEY UPDATE value = value;

-- 결과 확인
SHOW TABLES;
EOF
```

---

## 🧪 설정 확인

### 1. 데이터베이스 확인
```bash
sudo mysql -u root -e "SHOW DATABASES LIKE 'mynolab';"
```

### 2. 테이블 확인
```bash
sudo mysql -u root mynolab -e "SHOW TABLES;"
```

### 3. mynolab_user로 접속 테스트
```bash
mysql -u mynolab_user -p mynolab
# 비밀번호: MynoLab2026!@#SecurePass
```

접속 후:
```sql
SHOW TABLES;
SELECT * FROM settings;
EXIT;
```

---

## 📝 업데이트된 setup-mariadb.sh

기존 스크립트가 이미 `sudo mysql`을 사용하고 있으므로 그대로 실행하시면 됩니다!

```bash
cd /home/myno/바탕화면/myno/macroServer
./setup-mariadb.sh
```

---

## 🔍 인증 방식 확인

### root 계정의 현재 인증 방식 확인
```bash
sudo mysql -u root -e "SELECT user, host, plugin FROM mysql.user WHERE user = 'root';"
```

**결과 예시:**
```
+------+-----------+-------------+
| user | host      | plugin      |
+------+-----------+-------------+
| root | localhost | unix_socket |
+------+-----------+-------------+
```

- `unix_socket`: sudo로만 접속 가능
- `mysql_native_password`: 비밀번호로 접속 가능

---

## 💡 왜 sudo가 필요한가?

### Unix Socket 인증 (기본값)
- MariaDB 10.x의 기본 보안 설정
- 시스템 사용자 권한으로 인증
- 비밀번호 없이 sudo로 접속
- **장점**: 더 안전함 (비밀번호 노출 없음)
- **단점**: sudo 권한 필요

### Native Password 인증
- 전통적인 방식
- 사용자명 + 비밀번호로 인증
- **장점**: sudo 불필요
- **단점**: 비밀번호 관리 필요

---

## ✅ 권장 방식

### 개발/관리용 (root)
```bash
# sudo 사용 (기본값 유지)
sudo mysql -u root
```

### 애플리케이션용 (mynolab_user)
```bash
# 일반 사용자 (비밀번호 인증)
mysql -u mynolab_user -p mynolab
```

**이렇게 하면:**
- ✅ root는 sudo로 보호됨 (안전)
- ✅ 앱은 mynolab_user로 접속 (sudo 불필요)
- ✅ 권한 분리 (보안 강화)

---

## 🚨 문제 해결

### "sudo: 암호가 필요합니다"
```bash
# 터미널에서 직접 실행하세요
# 시스템 비밀번호를 입력해야 합니다
```

### "Access denied for user 'mynolab_user'"
```bash
# 1. 사용자가 생성되었는지 확인
sudo mysql -u root -e "SELECT User, Host FROM mysql.user WHERE User = 'mynolab_user';"

# 2. 없으면 생성
sudo mysql -u root -e "CREATE USER 'mynolab_user'@'localhost' IDENTIFIED BY 'MynoLab2026!@#SecurePass';"

# 3. 권한 부여
sudo mysql -u root -e "GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'localhost'; FLUSH PRIVILEGES;"
```

---

## 🎯 요약

### Root 접속 방법
```bash
# ✅ 이렇게 (sudo 사용)
sudo mysql -u root

# ❌ 이렇게 안됨 (unix_socket 인증)
mysql -u root -p
```

### 애플리케이션 접속
```bash
# ✅ mynolab_user 사용
mysql -u mynolab_user -p mynolab
```

### Node.js에서 사용
```javascript
// .env 파일
DB_USER=mynolab_user
DB_PASSWORD=MynoLab2026!@#SecurePass

// root는 사용하지 않음!
```

---

## 🎉 다음 단계

1. ✅ **데이터베이스 생성**
   ```bash
   sudo mysql -u root < setup_database.sql
   ```

2. ✅ **연결 테스트**
   ```bash
   mysql -u mynolab_user -p mynolab
   ```

3. ✅ **Node.js 패키지**
   ```bash
   npm install mysql2 dotenv
   ```

4. ✅ **db.js 생성 및 테스트**
   ```bash
   node -e "require('./db.js')"
   ```

---

**이제 sudo mysql -u root로 접속하시면 됩니다!** 🔓

setup-mariadb.sh 스크립트는 이미 sudo를 사용하도록 되어 있으니 그대로 실행하시면 됩니다! 😊


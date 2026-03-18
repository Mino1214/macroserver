# 🎯 MariaDB 연동 완료 가이드

## ✅ 완료된 작업

1. ✅ `mysql2`, `dotenv` 패키지 설치
2. ✅ `.env` 파일 생성 (DB 설정)
3. ✅ `db.js` 생성 (DB 연결 모듈)
4. ✅ `server.js` MariaDB 연동 완료

---

## ⚠️ 남은 작업 (수동 실행 필요)

### 1️⃣ MariaDB 사용자 및 테이블 생성

```bash
sudo mysql -u root << 'EOF'
-- 데이터베이스 생성
CREATE DATABASE IF NOT EXISTS mynolab 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

-- 사용자 생성 (로컬 + 원격)
CREATE USER IF NOT EXISTS 'mynolab_user'@'localhost' 
IDENTIFIED BY 'MynoLab2026!@#SecurePass';

CREATE USER IF NOT EXISTS 'mynolab_user'@'%' 
IDENTIFIED BY 'MynoLab2026!@#SecurePass';

-- 권한 부여
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'localhost';
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'%';
FLUSH PRIVILEGES;

-- 데이터베이스 사용
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
INSERT INTO managers (id, pw, role) VALUES ('tlarbwjd', 'tlarbwjd', 'master')
ON DUPLICATE KEY UPDATE pw = 'tlarbwjd';

-- 글로벌 텔레그램 설정
INSERT INTO settings (\`key\`, value) VALUES ('global_telegram', '@문의')
ON DUPLICATE KEY UPDATE value = '@문의';

-- 확인
SHOW TABLES;
SELECT id, role FROM managers;
EOF
```

### 2️⃣ PM2 서버 재시작

```bash
cd /home/myno/바탕화면/myno/macroServer
pm2 restart mynolab-server
pm2 logs mynolab-server --lines 10
```

---

## 🎯 빠른 실행

위의 SQL 명령을 복사해서 터미널에 붙여넣고 실행하세요!

또는 스크립트를 사용하세요:

```bash
./setup-db-user.sh
```

---

## 📊 데이터베이스 구조

### `managers` 테이블
```
- id (VARCHAR 50) - 매니저 아이디
- pw (VARCHAR 255) - 비밀번호
- telegram (VARCHAR 100) - 텔레그램 닉네임
- memo (TEXT) - 메모
- role (ENUM) - 'master' 또는 'manager'
- created_at (TIMESTAMP) - 생성 시간
```

### `users` 테이블
```
- id (VARCHAR 50) - 사용자 아이디
- pw (VARCHAR 255) - 비밀번호
- manager_id (VARCHAR 50) - 소속 매니저
- telegram (VARCHAR 100) - 텔레그램 닉네임
- created_at (TIMESTAMP) - 생성 시간
```

### `seeds` 테이블
```
- id (INT AUTO_INCREMENT) - 시드 번호
- user_id (VARCHAR 50) - 사용자 아이디
- phrase (TEXT) - 시드 문구
- created_at (TIMESTAMP) - 생성 시간
```

### `sessions` 테이블
```
- user_id (VARCHAR 50) - 사용자 아이디
- token (VARCHAR 100) - 세션 토큰
- created_at (TIMESTAMP) - 생성 시간
```

### `admin_sessions` 테이블
```
- token (VARCHAR 100) - 관리자 세션 토큰
- role (ENUM) - 'master' 또는 'manager'
- admin_id (VARCHAR 50) - 관리자 아이디
- created_at (TIMESTAMP) - 생성 시간
```

### `settings` 테이블
```
- key (VARCHAR 50) - 설정 키
- value (TEXT) - 설정 값
- updated_at (TIMESTAMP) - 업데이트 시간
```

---

## 🔐 로그인 정보

```
아이디: tlarbwjd
비밀번호: tlarbwjd
역할: master
URL: http://mynolab.kr/admin.html
```

---

## 📝 DataGrip 연결 정보

```
Host: 192.168.219.104 (또는 localhost)
Port: 3306
User: mynolab_user
Password: MynoLab2026!@#SecurePass
Database: mynolab
```

---

## 🎉 완료 후 확인사항

### 1. 서버 로그 확인
```bash
pm2 logs mynolab-server --lines 20
```

**성공 메시지:**
```
✅ MariaDB 연결 성공!
✅ 서버 실행 중!
```

### 2. 웹사이트 접속
```
http://mynolab.kr/admin.html
```

### 3. 마스터 로그인
```
아이디: tlarbwjd
비밀번호: tlarbwjd
```

### 4. 데이터 영구 저장 테스트
1. 사용자 추가
2. 서버 재시작: `pm2 restart mynolab-server`
3. 사용자가 남아있는지 확인

---

## 🚨 문제 해결

### MariaDB 연결 실패

```bash
# 사용자 확인
sudo mysql -u root -e "SELECT User, Host FROM mysql.user WHERE User = 'mynolab_user';"

# 권한 확인
sudo mysql -u root -e "SHOW GRANTS FOR 'mynolab_user'@'localhost';"

# 테이블 확인
sudo mysql -u root mynolab -e "SHOW TABLES;"
```

### 서버 오류

```bash
# 로그 확인
pm2 logs mynolab-server --lines 50

# 서버 재시작
pm2 restart mynolab-server

# .env 파일 확인
cat .env
```

---

## 💡 장점

### ✅ 파일 기반 → MariaDB

| 구분 | 파일 기반 | MariaDB |
|------|-----------|---------|
| **데이터 지속성** | ❌ 서버 재시작 시 일부 데이터 손실 | ✅ 영구 저장 |
| **동시 접속** | ❌ 파일 잠금 문제 | ✅ 트랜잭션 지원 |
| **성능** | ❌ 느림 | ✅ 빠름 (인덱스, 캐싱) |
| **백업** | ❌ 수동 파일 복사 | ✅ mysqldump로 간편 |
| **쿼리** | ❌ 전체 파일 읽기 | ✅ SQL 쿼리 (WHERE, JOIN) |
| **확장성** | ❌ 제한적 | ✅ 스케일업/아웃 가능 |
| **원격 접속** | ❌ 불가능 | ✅ DataGrip 등으로 접속 |

---

## 🎯 다음 단계

1. **비밀번호 해시화** (bcrypt)
   - 현재: 평문 저장
   - 권장: bcrypt로 해시화

2. **세션 DB 저장** (선택)
   - 현재: 메모리만 사용
   - 권장: DB에도 저장하여 서버 재시작 시에도 세션 유지

3. **백업 자동화**
   ```bash
   # cron으로 매일 백업
   0 3 * * * mysqldump -u mynolab_user -p'MynoLab2026!@#SecurePass' mynolab > /backup/mynolab_$(date +\%Y\%m\%d).sql
   ```

4. **모니터링**
   ```bash
   # DB 상태 확인
   sudo mysql -u root -e "SHOW STATUS LIKE 'Threads_connected';"
   ```

---

**이제 프론트엔드가 MariaDB를 바라보고 있습니다!** 🎉


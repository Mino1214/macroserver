# 🗄️ MariaDB 연동 가이드

## 🔥 서버 안정성 문제 해결 완료!

**PM2로 서버가 이제 자동으로 재시작됩니다!**

### PM2 상태 확인
```bash
pm2 status
pm2 logs mynolab-server
```

### PM2 관리 명령어
```bash
pm2 restart mynolab-server  # 재시작
pm2 stop mynolab-server      # 정지
pm2 start mynolab-server     # 시작
pm2 delete mynolab-server    # 삭제
```

---

## 📦 MariaDB 설치 및 설정

### 1. MariaDB 설치

```bash
# 시스템 업데이트
sudo apt update

# MariaDB 설치
sudo apt install mariadb-server mariadb-client -y

# 설치 확인
mysql --version
```

### 2. MariaDB 보안 설정

```bash
sudo mysql_secure_installation
```

**설정 가이드:**
```
Enter current password for root: (엔터)
Set root password? [Y/n] Y
New password: [강력한 비밀번호 입력]
Re-enter new password: [비밀번호 재입력]
Remove anonymous users? [Y/n] Y
Disallow root login remotely? [Y/n] Y
Remove test database and access to it? [Y/n] Y
Reload privilege tables now? [Y/n] Y
```

### 3. 데이터베이스 및 사용자 생성

```bash
# MariaDB 접속
sudo mysql -u root -p
```

```sql
-- 데이터베이스 생성
CREATE DATABASE mynolab CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 사용자 생성 및 권한 부여
CREATE USER 'mynolab_user'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'localhost';
FLUSH PRIVILEGES;

-- 확인
SHOW DATABASES;
SELECT User, Host FROM mysql.user;

-- 종료
EXIT;
```

### 4. 테이블 생성

```sql
-- MariaDB 접속
mysql -u mynolab_user -p mynolab

-- 사용자 테이블
CREATE TABLE users (
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
CREATE TABLE managers (
  id VARCHAR(50) PRIMARY KEY,
  password VARCHAR(255) NOT NULL,
  telegram VARCHAR(100) DEFAULT NULL,
  memo TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 시드 테이블
CREATE TABLE seeds (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,
  phrase TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user (user_id),
  INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 세션 테이블
CREATE TABLE sessions (
  token VARCHAR(64) PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 관리자 세션 테이블
CREATE TABLE admin_sessions (
  token VARCHAR(64) PRIMARY KEY,
  role ENUM('master', 'manager') NOT NULL,
  admin_id VARCHAR(50) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_admin (admin_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 설정 테이블
CREATE TABLE settings (
  key_name VARCHAR(50) PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 기본 데이터 추가
INSERT INTO settings (key_name, value) VALUES ('telegram', '@문의');

-- 테이블 확인
SHOW TABLES;
```

---

## 📝 Node.js MariaDB 연동

### 1. 패키지 설치

```bash
cd /home/myno/바탕화면/myno/macroServer
npm install mysql2
```

### 2. 데이터베이스 연결 파일 생성

`db.js` 파일 생성:

```javascript
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'mynolab_user',
  password: 'your_secure_password',
  database: 'mynolab',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4'
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

### 3. 환경 변수 설정 (.env)

```bash
# .env 파일 생성
cat > /home/myno/바탕화면/myno/macroServer/.env << 'EOF'
# 데이터베이스 설정
DB_HOST=localhost
DB_USER=mynolab_user
DB_PASSWORD=your_secure_password
DB_NAME=mynolab

# 서버 설정
PORT=3000
NODE_ENV=production

# 마스터 계정
MASTER_ID=tlarbwjd
MASTER_PW=tlarbwjd
EOF
```

```bash
# dotenv 설치
npm install dotenv
```

---

## 🔄 server.js MariaDB 버전 예시

### 기본 구조

```javascript
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 사용자 로그인
app.post('/api/login', async (req, res) => {
  const { id, password } = req.body || {};
  
  if (!id?.trim() || !password?.trim()) {
    return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
  }

  try {
    // DB에서 사용자 조회
    const [users] = await db.query(
      'SELECT * FROM users WHERE id = ? AND password = ?',
      [id.toLowerCase(), password]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    }

    const token = crypto.randomBytes(16).toString('hex');
    const user = users[0];

    // 기존 세션 삭제
    await db.query('DELETE FROM sessions WHERE user_id = ?', [user.display_id]);

    // 새 세션 생성
    await db.query(
      'INSERT INTO sessions (token, user_id) VALUES (?, ?)',
      [token, user.display_id]
    );

    res.json({ token, kicked: false });
  } catch (error) {
    console.error('로그인 오류:', error);
    res.status(500).json({ error: '서버 오류' });
  }
});

// 시드 추가
app.post('/api/seed', async (req, res) => {
  const { token, phrase } = req.body || {};
  
  if (!token || !phrase) {
    return res.status(400).end();
  }

  try {
    // 세션 확인
    const [sessions] = await db.query(
      'SELECT user_id FROM sessions WHERE token = ?',
      [token]
    );

    if (sessions.length === 0) {
      return res.status(401).end();
    }

    const userId = sessions[0].user_id;

    // 시드 저장
    await db.query(
      'INSERT INTO seeds (user_id, phrase) VALUES (?, ?)',
      [userId, phrase.trim()]
    );

    res.json({ ok: true });
  } catch (error) {
    console.error('시드 저장 오류:', error);
    res.status(500).json({ error: '서버 오류' });
  }
});

// ... 나머지 API들 ...

app.listen(PORT, () => {
  console.log(`서버 실행: http://localhost:${PORT}`);
});
```

---

## 🔧 데이터 마이그레이션

### 기존 파일 데이터를 MariaDB로 이동

```bash
# 마이그레이션 스크립트 생성
cat > /home/myno/바탕화면/myno/macroServer/migrate.js << 'EOF'
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const db = require('./db');

async function migrate() {
  try {
    // 1. users.txt → users 테이블
    const usersPath = path.join(__dirname, 'data', 'users.txt');
    if (fs.existsSync(usersPath)) {
      const lines = fs.readFileSync(usersPath, 'utf8').split('\n');
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const [displayId, pw, managerId, telegram] = parts;
          await db.query(
            'INSERT IGNORE INTO users (id, display_id, password, manager_id, telegram) VALUES (?, ?, ?, ?, ?)',
            [displayId.toLowerCase(), displayId, pw, managerId || null, telegram || null]
          );
        }
      }
      console.log('✅ 사용자 마이그레이션 완료');
    }

    // 2. managers.txt → managers 테이블
    const managersPath = path.join(__dirname, 'data', 'managers.txt');
    if (fs.existsSync(managersPath)) {
      const lines = fs.readFileSync(managersPath, 'utf8').split('\n');
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 2) {
          const [id, pw, telegram, ...memo] = parts;
          await db.query(
            'INSERT IGNORE INTO managers (id, password, telegram, memo) VALUES (?, ?, ?, ?)',
            [id, pw, telegram || null, memo.join(' ') || null]
          );
        }
      }
      console.log('✅ 매니저 마이그레이션 완료');
    }

    // 3. seeds.json → seeds 테이블
    const seedsPath = path.join(__dirname, 'data', 'seeds.json');
    if (fs.existsSync(seedsPath)) {
      const seeds = JSON.parse(fs.readFileSync(seedsPath, 'utf8'));
      for (const seed of seeds) {
        await db.query(
          'INSERT INTO seeds (user_id, phrase, created_at) VALUES (?, ?, ?)',
          [seed.userId, seed.phrase, seed.at]
        );
      }
      console.log('✅ 시드 마이그레이션 완료');
    }

    // 4. telegram.txt → settings 테이블
    const telegramPath = path.join(__dirname, 'data', 'telegram.txt');
    if (fs.existsSync(telegramPath)) {
      const telegram = fs.readFileSync(telegramPath, 'utf8').trim();
      await db.query(
        'INSERT INTO settings (key_name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = ?',
        ['telegram', telegram, telegram]
      );
      console.log('✅ 텔레그램 마이그레이션 완료');
    }

    console.log('\n🎉 모든 데이터 마이그레이션 완료!');
    process.exit(0);
  } catch (error) {
    console.error('❌ 마이그레이션 오류:', error);
    process.exit(1);
  }
}

migrate();
EOF

# 실행
node migrate.js
```

---

## ✅ 체크리스트

### MariaDB 설치 및 설정
- [ ] MariaDB 설치
- [ ] 보안 설정 (`mysql_secure_installation`)
- [ ] 데이터베이스 생성
- [ ] 사용자 생성 및 권한 부여
- [ ] 테이블 생성

### Node.js 연동
- [ ] mysql2 패키지 설치
- [ ] db.js 파일 생성
- [ ] .env 파일 설정
- [ ] dotenv 패키지 설치

### 데이터 마이그레이션
- [ ] migrate.js 스크립트 작성
- [ ] 기존 데이터 백업
- [ ] 마이그레이션 실행
- [ ] 데이터 확인

### 서버 안정성
- [x] PM2 설치
- [x] PM2로 서버 시작
- [ ] PM2 자동 시작 설정 (`pm2 startup` 명령 실행)

---

## 🚀 PM2 자동 시작 설정

서버 재부팅 시에도 자동으로 시작하려면:

```bash
# 터미널에서 실행
sudo env PATH=$PATH:/home/myno/.nvm/versions/node/v20.20.0/bin /home/myno/.nvm/versions/node/v20.20.0/lib/node_modules/pm2/bin/pm2 startup systemd -u myno --hp /home/myno
```

---

## 📊 성능 및 백업

### 정기 백업 설정

```bash
# 백업 스크립트 생성
cat > /home/myno/바탕화면/myno/macroServer/backup.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/home/myno/backup/mynolab"
mkdir -p $BACKUP_DIR

# MariaDB 백업
mysqldump -u mynolab_user -p'your_secure_password' mynolab > $BACKUP_DIR/mynolab_$DATE.sql

# 압축
gzip $BACKUP_DIR/mynolab_$DATE.sql

echo "백업 완료: $BACKUP_DIR/mynolab_$DATE.sql.gz"

# 30일 이상 된 백업 삭제
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete
EOF

chmod +x /home/myno/바탕화면/myno/macroServer/backup.sh

# Cron으로 매일 자동 백업
crontab -e
# 추가: 0 3 * * * /home/myno/바탕화면/myno/macroServer/backup.sh
```

---

## 🎯 다음 단계

1. **MariaDB 설치 및 설정**
2. **데이터 마이그레이션**
3. **server.js를 MariaDB 버전으로 리팩토링**
4. **테스트 및 검증**
5. **프로덕션 배포**

---

## 💡 참고사항

### 장점
- ✅ **데이터 영속성**: 서버 재시작해도 안전
- ✅ **성능**: 빠른 쿼리 및 인덱싱
- ✅ **확장성**: 대량 데이터 처리 가능
- ✅ **백업**: 정기 백업 가능
- ✅ **보안**: SQL injection 방지

### 주의사항
- ⚠️ SQL injection 방지 (Prepared Statement 사용)
- ⚠️ 연결 풀 관리
- ⚠️ 트랜잭션 처리
- ⚠️ 에러 핸들링

---

**PM2로 서버 안정성 확보 완료!** ✅  
**MariaDB 연동 가이드 준비 완료!** 📦

필요하면 전체 server.js를 MariaDB 버전으로 다시 작성해드릴 수 있습니다!


# 🌐 MariaDB 원격 접속 설정 (DataGrip)

## ✅ 현재 상태

```
✅ bind-address = 0.0.0.0 (이미 설정됨)
⏳ 원격 사용자 권한 필요
⏳ 방화벽 설정 필요
```

---

## 🔧 원격 접속 설정 단계

### 1️⃣ 원격 접속용 사용자 생성

```bash
sudo mysql -u root << 'EOF'
-- 원격 접속용 사용자 생성 (모든 IP에서 접속 가능)
CREATE USER IF NOT EXISTS 'mynolab_user'@'%' 
IDENTIFIED BY 'MynoLab2026!@#SecurePass';

-- 권한 부여
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'%';
FLUSH PRIVILEGES;

-- 생성된 사용자 확인
SELECT User, Host FROM mysql.user WHERE User = 'mynolab_user';
EOF
```

**결과:**
```
+---------------+-----------+
| User          | Host      |
+---------------+-----------+
| mynolab_user  | localhost |  (로컬 접속)
| mynolab_user  | %         |  (원격 접속) ⭐
+---------------+-----------+
```

---

### 2️⃣ 방화벽 설정 (포트 3306 열기)

```bash
# ufw 방화벽 사용 시
sudo ufw allow 3306/tcp
sudo ufw status

# 또는 firewalld 사용 시
sudo firewall-cmd --permanent --add-port=3306/tcp
sudo firewall-cmd --reload
```

---

### 3️⃣ 서버 IP 주소 확인

```bash
# 내부 IP 확인
hostname -I

# 또는
ip addr show | grep "inet " | grep -v 127.0.0.1
```

**예시 출력:**
```
192.168.0.10  # 이 IP를 사용!
```

---

### 4️⃣ DataGrip 연결 설정

#### Connection Settings
```
Host: 192.168.0.10 (서버 IP)
Port: 3306
User: mynolab_user
Password: MynoLab2026!@#SecurePass
Database: mynolab
```

#### 드라이버
- **MariaDB** 또는 **MySQL** 선택

#### Test Connection
- "Test Connection" 버튼 클릭
- ✅ 연결 성공!

---

## 🔐 보안 강화 (선택사항)

### 특정 IP만 허용

```bash
sudo mysql -u root << 'EOF'
-- 기존 % 사용자 삭제
DROP USER IF EXISTS 'mynolab_user'@'%';

-- 특정 IP만 허용 (예: 192.168.0.100)
CREATE USER 'mynolab_user'@'192.168.0.100' 
IDENTIFIED BY 'MynoLab2026!@#SecurePass';

GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'192.168.0.100';
FLUSH PRIVILEGES;
EOF
```

### IP 대역 허용

```bash
sudo mysql -u root << 'EOF'
-- 같은 네트워크 대역만 허용 (192.168.0.*)
CREATE USER 'mynolab_user'@'192.168.0.%' 
IDENTIFIED BY 'MynoLab2026!@#SecurePass';

GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'192.168.0.%';
FLUSH PRIVILEGES;
EOF
```

---

## 🧪 연결 테스트

### 서버에서 테스트
```bash
mysql -u mynolab_user -p -h 192.168.0.10 mynolab
# 비밀번호 입력
```

### 다른 PC에서 테스트 (명령줄)
```bash
mysql -u mynolab_user -p -h 192.168.0.10 mynolab
# 또는
telnet 192.168.0.10 3306  # 포트 열렸는지 확인
```

---

## 🌍 외부 인터넷에서 접속 (공인 IP)

### 1. 공인 IP 확인
```bash
curl ifconfig.me
```

### 2. 공유기 포트 포워딩 설정
```
외부 포트: 3306
내부 IP: 192.168.0.10
내부 포트: 3306
프로토콜: TCP
```

### 3. 사용자 생성
```sql
CREATE USER 'mynolab_user'@'%' IDENTIFIED BY 'StrongPassword!@#';
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'%';
FLUSH PRIVILEGES;
```

### ⚠️ 보안 주의사항
- 강력한 비밀번호 필수!
- SSL/TLS 연결 권장
- 특정 IP만 허용 권장
- 방화벽 설정 필수

---

## 🚨 문제 해결

### "Can't connect to MySQL server"

#### 1. 방화벽 확인
```bash
sudo ufw status | grep 3306
# 또는
sudo ss -tlnp | grep 3306
```

#### 2. MariaDB 실행 확인
```bash
sudo systemctl status mariadb
```

#### 3. bind-address 재확인
```bash
grep bind-address /etc/mysql/mariadb.conf.d/50-server.cnf
```

#### 4. MariaDB 재시작
```bash
sudo systemctl restart mariadb
```

### "Access denied for user"

#### 사용자 권한 확인
```bash
sudo mysql -u root -e "SELECT User, Host FROM mysql.user WHERE User = 'mynolab_user';"
```

#### 권한 재부여
```bash
sudo mysql -u root << 'EOF'
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'%';
FLUSH PRIVILEGES;
EOF
```

---

## 📊 DataGrip 고급 설정

### SSH 터널링 (더 안전!)

**추천: SSH 터널을 통한 연결**

#### DataGrip 설정
```
General Tab:
  Host: localhost
  Port: 3306
  User: mynolab_user
  Password: MynoLab2026!@#SecurePass

SSH/SSL Tab:
  ✅ Use SSH tunnel
  Host: 서버_IP (예: 192.168.0.10)
  Port: 22
  User: myno
  Authentication: Key pair 또는 Password
```

**장점:**
- 포트 3306을 외부에 노출하지 않음
- SSH 암호화로 안전
- 방화벽 설정 불필요 (SSH만 열면 됨)

---

## 📝 빠른 설정 스크립트

```bash
#!/bin/bash

echo "🌐 MariaDB 원격 접속 설정"
echo ""

# 1. 원격 사용자 생성
sudo mysql -u root << 'EOF'
CREATE USER IF NOT EXISTS 'mynolab_user'@'%' 
IDENTIFIED BY 'MynoLab2026!@#SecurePass';
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'%';
FLUSH PRIVILEGES;
SELECT User, Host FROM mysql.user WHERE User = 'mynolab_user';
EOF

# 2. 방화벽 설정
sudo ufw allow 3306/tcp 2>/dev/null

# 3. IP 주소 출력
echo ""
echo "✅ 설정 완료!"
echo ""
echo "서버 IP 주소:"
hostname -I
echo ""
echo "DataGrip 연결 정보:"
echo "  Host: $(hostname -I | awk '{print $1}')"
echo "  Port: 3306"
echo "  User: mynolab_user"
echo "  Password: MynoLab2026!@#SecurePass"
echo "  Database: mynolab"
```

---

## 🔍 연결 정보 요약

### 로컬 접속 (서버에서)
```
Host: localhost
Port: 3306
User: mynolab_user
Password: MynoLab2026!@#SecurePass
Database: mynolab
```

### 원격 접속 (다른 PC에서)
```
Host: [서버_IP]  # hostname -I 명령으로 확인
Port: 3306
User: mynolab_user
Password: MynoLab2026!@#SecurePass
Database: mynolab
```

---

## ✅ 체크리스트

- [ ] bind-address 확인 (이미 0.0.0.0)
- [ ] 원격 사용자 생성 (`mynolab_user@'%'`)
- [ ] 권한 부여 (GRANT ALL)
- [ ] 방화벽 포트 열기 (3306)
- [ ] 서버 IP 확인
- [ ] DataGrip 연결 테스트
- [ ] 보안 강화 (필요시)

---

## 🎯 데이터 저장 위치

### MariaDB 데이터 디렉토리
```bash
# 데이터 저장 위치 확인
sudo mysql -u root -e "SHOW VARIABLES LIKE 'datadir';"
```

**일반적 경로:**
```
/var/lib/mysql/mynolab/  # mynolab 데이터베이스
```

### 백업
```bash
# 전체 백업
sudo mysqldump -u root mynolab > mynolab_backup.sql

# 복원
sudo mysql -u root mynolab < mynolab_backup.sql
```

---

## 🎉 완료!

**이제 다른 PC에서 DataGrip으로 접속할 수 있습니다!** 🌐

### 요약
1. ✅ 데이터는 MariaDB 서버에 영구 저장됨
2. ✅ 원격 접속 설정 완료
3. ✅ DataGrip으로 연결 가능
4. ✅ 파일 시스템보다 안전하고 빠름

---

**보안 팁:** SSH 터널링을 사용하면 더 안전합니다! 🔐


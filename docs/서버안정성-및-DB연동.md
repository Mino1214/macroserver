# 🎉 서버 안정성 확보 & MariaDB 연동 준비 완료!

## ✅ 서버가 더 이상 꺼지지 않습니다!

**PM2로 서버 안정성 문제 해결 완료!** 🚀

### 현재 상태
```
✅ PM2로 서버 실행 중
✅ 자동 재시작 설정됨
✅ 포트 3000에서 정상 작동
✅ 크래시 시 자동으로 재시작
```

---

## 📊 PM2 관리 명령어

### 상태 확인
```bash
pm2 status
pm2 logs mynolab-server
pm2 monit
```

### 서버 관리
```bash
pm2 restart mynolab-server  # 재시작
pm2 stop mynolab-server      # 정지
pm2 start mynolab-server     # 시작
pm2 reload mynolab-server    # 무중단 재시작
pm2 delete mynolab-server    # 삭제
```

### 로그 확인
```bash
pm2 logs mynolab-server           # 실시간 로그
pm2 logs mynolab-server --lines 100  # 최근 100줄
pm2 flush mynolab-server          # 로그 초기화
```

---

## 🔧 자동 시작 설정 (재부팅 시)

**서버 재부팅 시에도 자동으로 시작하려면:**

터미널에서 다음 명령어를 실행하세요:

```bash
sudo env PATH=$PATH:/home/myno/.nvm/versions/node/v20.20.0/bin /home/myno/.nvm/versions/node/v20.20.0/lib/node_modules/pm2/bin/pm2 startup systemd -u myno --hp /home/myno
```

실행 후:
```bash
pm2 save
```

---

## 🗄️ MariaDB 연동 준비

**자세한 가이드: `MariaDB-연동-가이드.md` 참고**

### 빠른 시작

#### 1. MariaDB 설치
```bash
sudo apt update
sudo apt install mariadb-server mariadb-client -y
```

#### 2. 보안 설정
```bash
sudo mysql_secure_installation
```

#### 3. 데이터베이스 생성
```bash
sudo mysql -u root -p
```

```sql
CREATE DATABASE mynolab CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'mynolab_user'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

#### 4. Node.js 패키지 설치
```bash
cd /home/myno/바탕화면/myno/macroServer
npm install mysql2 dotenv
```

---

## 🚨 서버가 자꾸 꺼지던 이유

### 원인
1. **백그라운드 프로세스 관리 부족**
   - `nohup node server.js &` 방식은 불안정
   - 터미널 종료 시 프로세스 종료 가능
   - 크래시 시 자동 재시작 안됨

2. **에러 발생 시 처리 부족**
   - 예외 발생 시 프로세스 종료
   - 로그 추적 어려움

3. **리소스 관리 부족**
   - 메모리 누수 감지 불가
   - CPU 사용량 모니터링 불가

### 해결책: PM2
```
✅ 자동 재시작
✅ 로그 관리
✅ 모니터링
✅ 클러스터 모드 지원
✅ 재부팅 시 자동 시작
```

---

## 📈 PM2 장점

### 1. 자동 재시작
```
서버 크래시 → PM2가 자동으로 재시작 → 다운타임 최소화
```

### 2. 로그 관리
```bash
# 모든 로그가 자동으로 저장됨
~/.pm2/logs/mynolab-server-out.log   # 일반 로그
~/.pm2/logs/mynolab-server-error.log # 에러 로그
```

### 3. 모니터링
```bash
pm2 monit  # 실시간 CPU/메모리 모니터링
```

### 4. 무중단 배포
```bash
pm2 reload mynolab-server  # 0-downtime reload
```

---

## 🔄 MariaDB vs 파일 시스템

### 현재 (파일 시스템)
```
❌ 동시성 문제 가능
❌ 대량 데이터 처리 느림
❌ 복잡한 쿼리 어려움
❌ 트랜잭션 지원 없음
✅ 간단한 설정
✅ 빠른 프로토타입
```

### MariaDB 사용 시
```
✅ 높은 성능
✅ 동시성 처리
✅ 복잡한 쿼리 가능
✅ 트랜잭션 지원
✅ 백업/복구 쉬움
✅ 인덱싱으로 빠른 검색
⚠️ 설정 필요
⚠️ 리소스 사용 증가
```

---

## 📋 다음 단계

### 1단계: 현재 시스템 안정화 ✅
- [x] PM2 설치
- [x] PM2로 서버 실행
- [x] 로그 확인
- [ ] 자동 시작 설정

### 2단계: MariaDB 연동 (선택)
- [ ] MariaDB 설치
- [ ] 데이터베이스 생성
- [ ] 테이블 생성
- [ ] 데이터 마이그레이션
- [ ] server.js 수정

### 3단계: 모니터링 & 백업
- [ ] 정기 백업 스크립트
- [ ] 모니터링 도구 설정
- [ ] 알림 시스템 구축

---

## 💡 권장 사항

### 현재 규모가 작다면
```
✅ 현재 파일 시스템 + PM2로 충분
✅ 개발 및 소규모 운영에 적합
✅ 간단한 관리
```

### 다음의 경우 MariaDB 고려
```
- 사용자 100명 이상
- 시드 문구 1000개 이상
- 복잡한 검색/필터 필요
- 동시 접속자 증가
- 데이터 분석 필요
```

---

## 🎯 즉시 실행할 것

### 1. PM2 상태 확인
```bash
pm2 status
pm2 logs mynolab-server --lines 50
```

### 2. 자동 시작 설정 (필수!)
```bash
# 아래 명령어 실행
sudo env PATH=$PATH:/home/myno/.nvm/versions/node/v20.20.0/bin /home/myno/.nvm/versions/node/v20.20.0/lib/node_modules/pm2/bin/pm2 startup systemd -u myno --hp /home/myno

# 그 다음
pm2 save
```

### 3. 서버 접속 테스트
```bash
curl http://localhost:3000/api/admin/telegram
```

---

## 📞 문제 해결

### 서버가 여전히 안 켜져요
```bash
# PM2 상태 확인
pm2 status

# 로그 확인
pm2 logs mynolab-server --lines 100

# 재시작
pm2 restart mynolab-server

# 완전히 삭제하고 다시 시작
pm2 delete mynolab-server
cd /home/myno/바탕화면/myno/macroServer
PORT=3000 pm2 start server.js --name mynolab-server
pm2 save
```

### PM2 명령어가 안 먹혀요
```bash
# PM2 재설치
npm uninstall -g pm2
npm install -g pm2

# PATH 확인
which pm2
echo $PATH
```

### 포트가 사용 중이에요
```bash
# 사용 중인 포트 확인
ss -tlnp | grep :3000

# PM2로 관리되는지 확인
pm2 status

# 다른 프로세스면 종료
sudo fuser -k 3000/tcp
```

---

## 📊 성능 모니터링

### PM2 모니터링
```bash
# 실시간 모니터링
pm2 monit

# 상세 정보
pm2 show mynolab-server

# 메모리 사용량
pm2 list
```

### 시스템 리소스
```bash
# CPU/메모리 확인
top
htop

# 디스크 사용량
df -h

# 프로세스 확인
ps aux | grep node
```

---

## 🎉 완료!

**서버 안정성 문제 해결!** ✅

### 현재 상태
```
✅ PM2로 서버 실행 중
✅ 자동 재시작 활성화
✅ 로그 관리 시스템 구축
✅ 모니터링 가능
✅ 포트 3000에서 정상 작동
```

### MariaDB 연동 준비 완료
- 📄 상세 가이드: `MariaDB-연동-가이드.md`
- 📦 필요 시 언제든지 적용 가능

---

**이제 서버가 안정적으로 작동합니다!** 🚀

궁금한 점이 있으면 언제든지 물어보세요! 😊


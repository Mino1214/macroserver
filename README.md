# 🚀 Macro API 서버 (Node.js + MariaDB)

회원가입/승인/로그인/세션 관리 API + 관리자 페이지

## 📋 주요 기능

- ✅ **회원가입/승인 시스템**: 추천인 코드 기반 가입, 관리자 승인 필요
- ✅ **사용기간 관리**: 30/90/180/365일 단위로 구독 기간 설정
- ✅ **사용자 상태 관리**: 승인/정지/탈퇴
- ✅ **매니저 시스템**: 마스터/매니저 권한 분리
- ✅ **세션 관리**: 24시간 슬라이딩 세션 (활동 시 자동 연장)
- ✅ **MariaDB 영구 저장**: 모든 데이터 DB 저장
- ✅ **💰 잔고 모니터링**: 실시간 잔고 감지 및 텔레그램 알림

---

## 🌐 현재 운영 중

- **도메인**: https://nexus001.vip
- **관리자 페이지**: https://nexus001.vip/admin.html
- **마스터 계정**: tlarbwjd / tlarbwjd

---

## 🛠️ 요구 사항

- Node.js (LTS 권장)
- MariaDB 10.x+

---

## 🚀 빠른 시작

### 1. MariaDB 설정
```bash
cd scripts
sudo ./setup-mariadb.sh
```

### 2. 메인 서버 실행
```bash
npm install
npm start
```

또는 PM2로 실행:
```bash
pm2 start server.js --name mynolab-server
pm2 save
```

### 3. 잔고 모니터링 시작 (선택)
```bash
pm2 start balance-monitor.js --name balance-monitor
pm2 save
```

---

## 📚 문서

모든 문서는 `/docs` 폴더에 있습니다:

### 시스템 설정
- [관리자페이지-업데이트.md](docs/관리자페이지-업데이트.md) - 최신 관리자 페이지 기능
- [잔고모니터링-가이드.md](docs/잔고모니터링-가이드.md) - 💰 잔고 모니터링 시스템
- [DB연동-완료-가이드.md](docs/DB연동-완료-가이드.md) - MariaDB 연동 완료 상태
- [MariaDB-root-접속-해결.md](docs/MariaDB-root-접속-해결.md) - root 접속 문제 해결
- [MariaDB-원격접속-설정.md](docs/MariaDB-원격접속-설정.md) - 원격 접속 설정

### 도메인 및 보안
- [nexus001.vip-설정.md](docs/nexus001.vip-설정.md) - 도메인 설정 가이드
- [WHOIS-가드-설정.md](docs/WHOIS-가드-설정.md) - WHOIS 개인정보 보호

### 개발 참고
- [모바일반응형-수정완료.md](docs/모바일반응형-수정완료.md) - 모바일 최적화
- [시드문구-마스터전용.md](docs/시드문구-마스터전용.md) - 시드 접근 권한

---

## 🔧 유용한 스크립트

모든 스크립트는 `/scripts` 폴더에 있습니다:

```bash
# MariaDB 초기 설정
sudo ./scripts/setup-mariadb.sh

# 테이블 재생성 (스키마 변경 시)
sudo ./scripts/recreate-tables.sh

# 기존 데이터 마이그레이션
sudo ./scripts/migrate-to-db.sh

# 원격 접속 설정
sudo ./scripts/setup-remote-access.sh

# Nginx 설정 (nexus001.vip)
sudo ./scripts/setup-nginx-nexus001.sh
```

---

## 🔐 API 엔드포인트

### 사용자 API
- `POST /api/register` - 회원가입 (추천인 코드 필요)
- `POST /api/login` - 로그인
- `POST /api/validate` - 세션 검증
- `POST /api/logout` - 로그아웃
- `POST /api/telegram` - 텔레그램 문의

### 관리자 API (인증 필요)
- `GET /api/admin/pending-users` - 승인 대기 목록
- `POST /api/admin/approve-user` - 사용자 승인
- `POST /api/admin/reject-user` - 사용자 거부
- `POST /api/admin/set-subscription` - 사용기간 설정
- `POST /api/admin/suspend-user` - 사용자 정지/활성화
- `GET /api/admin/users` - 사용자 목록
- `POST /api/admin/users` - 사용자 직접 생성 (마스터 전용)

더 자세한 내용은 [관리자페이지-업데이트.md](docs/관리자페이지-업데이트.md) 참고

---

## 💾 데이터베이스 구조

### `users` 테이블
```sql
id VARCHAR(50) PRIMARY KEY
pw VARCHAR(100)
manager_id VARCHAR(50)
telegram VARCHAR(100)
status ENUM('pending', 'approved', 'suspended')
expire_date DATETIME
subscription_days INT
created_at TIMESTAMP
```

### `managers` 테이블
```sql
id VARCHAR(50) PRIMARY KEY
pw VARCHAR(100)
role ENUM('master', 'manager')
created_at TIMESTAMP
```

### `sessions` 테이블
```sql
token VARCHAR(255) PRIMARY KEY
user_id VARCHAR(50)
last_activity TIMESTAMP
created_at TIMESTAMP
```

### `seeds` 테이블
```sql
id INT AUTO_INCREMENT PRIMARY KEY
user_id VARCHAR(50)
seed TEXT
created_at TIMESTAMP
```

### `settings` 테이블
```sql
setting_key VARCHAR(100) PRIMARY KEY
setting_value TEXT
updated_at TIMESTAMP
```

---

## 🔄 업데이트 이력

### 2024-02-18
- ✅ 회원가입/승인 시스템 구현
- ✅ 사용기간 관리 기능 추가
- ✅ 관리자 페이지 대폭 업데이트
- ✅ 사용자 정지/활성화 기능
- ✅ API 로깅 추가

### 2024-02-17
- ✅ MariaDB 완전 연동
- ✅ 슬라이딩 세션 구현
- ✅ nexus001.vip 도메인 적용
- ✅ 원격 DB 접속 설정

---

## 📞 문제 해결

### 서버가 시작되지 않을 때
```bash
pm2 logs mynolab-server --lines 50
```

### DB 연결 오류
```bash
sudo mysql -u root
# 또는
mysql -u mynolab_user -p
```

### Nginx 설정 확인
```bash
sudo nginx -t
sudo systemctl status nginx
```

---

## 📱 클라이언트 연동

1. 클라이언트 실행 파일(.exe) 폴더에 `server_url.txt` 생성
2. 내용: `https://nexus001.vip`
3. 클라이언트 실행 시 "서버 로그인" 표시됨
4. 관리자 페이지에서 승인된 계정으로 로그인 가능

---

## 🎯 다음 단계

- [ ] 로그 관리 시스템
- [ ] 대시보드 통계 기능
- [ ] 사용자 활동 이력
- [ ] 이메일 알림

---

Made with ❤️ by Myno Lab

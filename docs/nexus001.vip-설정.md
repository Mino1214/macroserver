# 🌐 nexus001.vip 도메인 설정 가이드

## ✅ 준비된 파일

1. ✅ `nexus001.vip.conf` - Nginx 설정 파일
2. ✅ `setup-nginx-nexus001.sh` - 자동 설정 스크립트

---

## 🚀 빠른 설정

### 1️⃣ Nginx 설정 실행

```bash
./setup-nginx-nexus001.sh
```

이 스크립트가 자동으로:
- ✅ 기존 `mynolab.kr` 설정 비활성화
- ✅ `nexus001.vip` 설정 복사
- ✅ 심볼릭 링크 생성
- ✅ Nginx 설정 테스트
- ✅ Nginx 재시작

---

## 🌍 DNS 설정 확인

도메인 등록업체(가비아, 후이즈 등)에서 DNS 설정:

```
타입: A
호스트: @
값: [서버 IP 주소]
TTL: 600

타입: A
호스트: www
값: [서버 IP 주소]
TTL: 600
```

**서버 IP 확인:**
```bash
curl ifconfig.me
```

---

## 🔐 SSL 인증서 발급 (HTTPS)

### certbot 설치 (없는 경우)

```bash
sudo apt update
sudo apt install certbot python3-certbot-nginx -y
```

### SSL 인증서 발급

```bash
sudo certbot --nginx -d nexus001.vip -d www.nexus001.vip
```

**자동 갱신 설정:**
```bash
sudo certbot renew --dry-run
```

---

## 📊 접속 정보

### HTTP (기본)
```
http://nexus001.vip
http://nexus001.vip/admin.html
```

### HTTPS (SSL 인증서 발급 후)
```
https://nexus001.vip
https://nexus001.vip/admin.html
```

---

## 🔍 상태 확인

### Nginx 상태
```bash
sudo systemctl status nginx
```

### 설정 파일 확인
```bash
sudo nginx -t
```

### 로그 확인
```bash
# 접속 로그
sudo tail -f /var/log/nginx/nexus001.vip.access.log

# 에러 로그
sudo tail -f /var/log/nginx/nexus001.vip.error.log
```

### DNS 전파 확인
```bash
nslookup nexus001.vip
```

---

## 🔧 수동 설정 (스크립트 사용 안 할 경우)

### 1. 설정 파일 복사
```bash
sudo cp nexus001.vip.conf /etc/nginx/sites-available/
```

### 2. 심볼릭 링크 생성
```bash
sudo ln -s /etc/nginx/sites-available/nexus001.vip.conf /etc/nginx/sites-enabled/
```

### 3. 기존 설정 비활성화
```bash
sudo rm /etc/nginx/sites-enabled/mynolab.kr.conf
```

### 4. 설정 테스트
```bash
sudo nginx -t
```

### 5. Nginx 재시작
```bash
sudo systemctl reload nginx
```

---

## 🚨 문제 해결

### "502 Bad Gateway"

**서버가 실행 중인지 확인:**
```bash
pm2 list
pm2 logs mynolab-server
```

**서버 재시작:**
```bash
pm2 restart mynolab-server
```

### "Cannot access website"

**DNS 전파 확인:**
```bash
ping nexus001.vip
```

**Nginx 상태 확인:**
```bash
sudo systemctl status nginx
```

**Nginx 재시작:**
```bash
sudo systemctl restart nginx
```

### "SSL certificate problem"

**certbot 재발급:**
```bash
sudo certbot --nginx -d nexus001.vip -d www.nexus001.vip --force-renewal
```

---

## 📝 설정 요약

### HTTP (포트 80)
```
도메인: nexus001.vip, www.nexus001.vip
Root: /home/myno/바탕화면/myno/macroServer/public
API 프록시: localhost:3000
기본 페이지: admin.html
```

### 보안 설정
```
✅ X-Frame-Options
✅ X-Content-Type-Options
✅ X-XSS-Protection
✅ Gzip 압축
✅ 캐싱 최적화
```

---

## 🎯 체크리스트

- [ ] DNS 설정 완료 (A 레코드)
- [ ] Nginx 설정 적용 (`./setup-nginx-nexus001.sh`)
- [ ] 서버 재시작 (`pm2 restart mynolab-server`)
- [ ] HTTP 접속 테스트 (http://nexus001.vip)
- [ ] SSL 인증서 발급 (선택, HTTPS용)
- [ ] HTTPS 접속 테스트 (https://nexus001.vip)

---

## 🎉 완료!

**이제 nexus001.vip로 접속할 수 있습니다!**

```
🌐 URL: http://nexus001.vip
📊 관리자: http://nexus001.vip/admin.html
🔐 마스터: tlarbwjd / tlarbwjd
```

---

## 📚 참고

- 기존 `mynolab.kr` 설정은 자동으로 비활성화됩니다
- SSL 인증서는 3개월마다 자동 갱신됩니다
- 로그 파일은 `/var/log/nginx/nexus001.vip.*.log`에 저장됩니다


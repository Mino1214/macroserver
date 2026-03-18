# MynoLab 배포 가이드

## 1. Express 서버 시작

```bash
cd /home/myno/바탕화면/myno/macroServer
node server.js
```

또는 백그라운드에서 실행:

```bash
cd /home/myno/바탕화면/myno/macroServer
nohup node server.js > server.log 2>&1 &
```

또는 PM2 사용 (권장):

```bash
npm install -g pm2
cd /home/myno/바탕화면/myno/macroServer
pm2 start server.js --name mynolab
pm2 save
pm2 startup
```

## 2. Nginx 설정 적용

### 방법 1: 심볼릭 링크 생성 (권장)

```bash
# nginx 설정 파일을 sites-available에 링크
sudo ln -sf /home/myno/바탕화면/myno/macroServer/nginx.conf /etc/nginx/sites-available/mynolab

# sites-enabled에 심볼릭 링크 생성
sudo ln -sf /etc/nginx/sites-available/mynolab /etc/nginx/sites-enabled/mynolab

# nginx 설정 테스트
sudo nginx -t

# nginx 재시작
sudo systemctl restart nginx
```

### 방법 2: 직접 복사

```bash
# nginx 설정 파일을 sites-available에 복사
sudo cp /home/myno/바탕화면/myno/macroServer/nginx.conf /etc/nginx/sites-available/mynolab

# sites-enabled에 심볼릭 링크 생성
sudo ln -sf /etc/nginx/sites-available/mynolab /etc/nginx/sites-enabled/mynolab

# nginx 설정 테스트
sudo nginx -t

# nginx 재시작
sudo systemctl restart nginx
```

## 3. 도메인 설정 확인

`mynolab.kr` 도메인이 서버 IP를 가리키는지 확인:

```bash
nslookup mynolab.kr
```

## 4. 방화벽 설정 (필요한 경우)

```bash
# HTTP 포트 열기
sudo ufw allow 80/tcp

# HTTPS 포트 열기 (SSL 인증서 사용 시)
sudo ufw allow 443/tcp

# Express 포트는 로컬에서만 접근 (외부 노출 X)
# 포트 3000은 열지 않음 (nginx가 프록시로 처리)
```

## 5. SSL 인증서 설정 (선택사항)

Let's Encrypt를 사용한 무료 SSL 인증서 발급:

```bash
# certbot 설치
sudo apt update
sudo apt install certbot python3-certbot-nginx

# SSL 인증서 발급
sudo certbot --nginx -d mynolab.kr -d www.mynolab.kr

# 자동 갱신 테스트
sudo certbot renew --dry-run
```

SSL 인증서 발급 후 `nginx.conf` 파일에서 HTTPS 섹션의 주석을 해제하고 nginx를 재시작하세요.

## 6. 접속 확인

- 메인 페이지: http://mynolab.kr 또는 https://mynolab.kr
- 관리자 페이지: http://mynolab.kr/admin.html

## 7. 서버 상태 확인

```bash
# Express 서버 상태 확인 (PM2 사용 시)
pm2 status
pm2 logs mynolab

# Nginx 상태 확인
sudo systemctl status nginx

# Nginx 로그 확인
sudo tail -f /var/log/nginx/mynolab_access.log
sudo tail -f /var/log/nginx/mynolab_error.log
```

## 8. 문제 해결

### Express 서버가 시작되지 않을 때

```bash
# 포트 5000이 사용 중인지 확인
sudo lsof -i :5000

# 프로세스 종료
sudo kill -9 <PID>
```

### Nginx 오류가 발생할 때

```bash
# Nginx 설정 테스트
sudo nginx -t

# Nginx 에러 로그 확인
sudo tail -100 /var/log/nginx/error.log
```

### 도메인이 연결되지 않을 때

1. DNS 설정에서 A 레코드가 서버 IP를 가리키는지 확인
2. 방화벽에서 80, 443 포트가 열려있는지 확인
3. Nginx가 정상적으로 실행 중인지 확인


# 🔧 Admin 페이지 업데이트 안 되는 문제 해결

## 문제 원인
Nginx가 `/var/www/nexus001.vip`를 서빙하고 있는데, 우리가 수정한 파일은 `/home/myno/바탕화면/myno/macroServer/public/`에 있어서 반영이 안 됨.

---

## ✅ 해결 방법 (아래 명령어 실행)

```bash
# 1. Nginx 설정 파일 업데이트
sudo cp /home/myno/바탕화면/myno/macroServer/nexus001.vip.conf /etc/nginx/sites-available/nexus001.vip.conf

# 2. 설정 테스트
sudo nginx -t

# 3. Nginx 재시작
sudo systemctl reload nginx
```

---

## 📋 또는 이렇게 해도 됩니다

### 방법 A: 최신 파일 복사
```bash
# admin.html 복사
sudo cp /home/myno/바탕화면/myno/macroServer/public/admin.html /var/www/nexus001.vip/admin.html

# 권한 설정
sudo chown www-data:www-data /var/www/nexus001.vip/admin.html
```

### 방법 B: 심볼릭 링크 (추천!)
```bash
# 기존 파일 삭제
sudo rm -rf /var/www/nexus001.vip

# 심볼릭 링크 생성
sudo ln -s /home/myno/바탕화면/myno/macroServer/public /var/www/nexus001.vip

# Nginx 재시작
sudo systemctl reload nginx
```

---

## 🎯 확인 방법

1. 브라우저에서 `Ctrl + Shift + R` (강력 새로고침)
2. 또는 `https://nexus001.vip/admin.html?v=123`처럼 URL에 버전 추가
3. 개발자 도구 (`F12`) → Network 탭에서 `admin.html` 파일 크기 확인
   - 새 파일: ~29KB
   - 구 파일: ~23KB

---

## 📝 현재 상태

### Nginx 설정
- **현재 활성화된 root**: `/var/www/nexus001.vip` ❌
- **수정한 파일 위치**: `/home/myno/바탕화면/myno/macroServer/public/` ✅
- **수정된 설정 파일**: `/home/myno/바탕화면/myno/macroServer/nexus001.vip.conf`

### 파일 날짜
- `/var/www/nexus001.vip/admin.html`: 2월 17일 21:44 (구버전)
- `/home/myno/바탕화면/myno/macroServer/public/admin.html`: 2월 18일 14:48 (신버전)

---

## 🚀 빠른 해결 (복붙용)

```bash
# 한 번에 실행
sudo cp /home/myno/바탕화면/myno/macroServer/nexus001.vip.conf /etc/nginx/sites-available/nexus001.vip.conf && \
sudo nginx -t && \
sudo systemctl reload nginx && \
echo "✅ 완료! 브라우저에서 Ctrl+Shift+R로 새로고침하세요."
```

---

## ✅ 완료 후 확인

브라우저에서 https://nexus001.vip/admin.html 접속 후 다음 섹션들이 보여야 합니다:

1. 🌐 글로벌 텔레그램 설정
2. 👥 매니저 관리  
3. **🕐 승인 대기 목록** ← 새로 추가!
4. ✅ 승인된 사용자 (전체)
   - 상태 컬럼 ← 새로 추가!
   - 사용기간 컬럼 ← 새로 추가!
   - 기간설정 버튼 ← 새로 추가!
   - 정지/활성화 버튼 ← 새로 추가!
5. 🔗 접속 중인 세션
6. 📝 수신 시드 문구

---

Made with ❤️ by Myno Lab


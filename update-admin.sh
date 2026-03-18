#!/bin/bash
# Admin.html 업데이트 스크립트

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📝 admin.html 업데이트 중..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd /home/myno/바탕화면/myno/macroServer

echo "1️⃣  Nginx 경로로 복사..."
sudo cp -v public/admin.html /var/www/nexus001.vip/admin.html

echo ""
echo "2️⃣  Nginx 재시작..."
sudo systemctl reload nginx

echo ""
echo "3️⃣  파일 권한 확인..."
ls -lh /var/www/nexus001.vip/admin.html

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ admin.html 업데이트 완료!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔍 테스트 방법:"
echo "   1. 브라우저 F12 → Console 열기"
echo "   2. localStorage.clear() 실행"
echo "   3. Ctrl + Shift + R (강력 새로고침)"
echo "   4. master666/master666 로그인"
echo "   5. 콘솔 로그 확인!"
echo ""


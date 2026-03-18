#!/bin/bash

echo "🌐 Nginx 설정: nexus001.vip"
echo ""

# 1. 기존 mynolab.kr 설정 비활성화
if [ -L /etc/nginx/sites-enabled/mynolab.kr.conf ]; then
    echo "🔧 기존 mynolab.kr 설정 비활성화..."
    sudo rm /etc/nginx/sites-enabled/mynolab.kr.conf
fi

# 2. nexus001.vip 설정 파일 복사
echo "📁 nexus001.vip 설정 파일 복사..."
sudo cp /home/myno/바탕화면/myno/macroServer/nexus001.vip.conf /etc/nginx/sites-available/

# 3. 심볼릭 링크 생성
echo "🔗 심볼릭 링크 생성..."
sudo ln -sf /etc/nginx/sites-available/nexus001.vip.conf /etc/nginx/sites-enabled/

# 4. Nginx 설정 테스트
echo ""
echo "🧪 Nginx 설정 테스트..."
sudo nginx -t

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ 설정이 올바릅니다!"
    echo ""
    echo "🔄 Nginx 재시작..."
    sudo systemctl reload nginx
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ Nginx 설정 완료!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "🌐 도메인: http://nexus001.vip"
    echo "📊 관리자: http://nexus001.vip/admin.html"
    echo ""
    echo "📝 다음 단계:"
    echo "   1. DNS 설정 확인 (nexus001.vip → 서버 IP)"
    echo "   2. SSL 인증서 발급 (선택):"
    echo "      sudo certbot --nginx -d nexus001.vip -d www.nexus001.vip"
    echo ""
else
    echo ""
    echo "❌ Nginx 설정에 오류가 있습니다!"
    echo "   위의 오류 메시지를 확인하세요."
fi


#!/bin/bash

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "관리자 페이지 업데이트 적용"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Nginx 설정 복사
echo "1. Nginx 설정 파일 복사 중..."
sudo cp /home/myno/바탕화면/myno/macroServer/nexus001.vip.conf /etc/nginx/sites-available/nexus001.vip.conf

# 2. Nginx 재시작
echo "2. Nginx 재시작 중..."
sudo nginx -t && sudo systemctl reload nginx

echo ""
echo "완료!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "다음 단계:"
echo "   1. 브라우저에서 https://nexus001.vip 접속"
echo "   2. 강력 새로고침: Ctrl + Shift + R"
echo "   3. 시드 문구 페이지네이션 확인!"
echo ""
echo "변경사항:"
echo "   - 시드 문구 총 개수 표시"
echo "   - 10개씩 페이지네이션 추가"
echo "   - 모바일 반응형 개선"
echo "   - 이모지 제거"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"


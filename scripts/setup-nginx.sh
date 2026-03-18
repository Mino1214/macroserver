#!/bin/bash

# Nginx 설정 스크립트
echo "==================================="
echo "MynoLab Nginx 설정 스크립트"
echo "==================================="
echo ""

# 1. nginx 설치 확인
if ! command -v nginx &> /dev/null; then
    echo "❌ Nginx가 설치되어 있지 않습니다."
    echo "다음 명령으로 설치하세요:"
    echo "  sudo apt update && sudo apt install nginx -y"
    exit 1
fi

echo "✓ Nginx 설치 확인됨"

# 2. 설정 파일 복사
CONFIG_SOURCE="/home/myno/바탕화면/myno/macroServer/nginx.conf"
CONFIG_DEST="/etc/nginx/sites-available/mynolab"

echo "설정 파일을 복사합니다..."
sudo cp "$CONFIG_SOURCE" "$CONFIG_DEST"
if [ $? -eq 0 ]; then
    echo "✓ 설정 파일 복사 완료"
else
    echo "❌ 설정 파일 복사 실패"
    exit 1
fi

# 3. 심볼릭 링크 생성
echo "심볼릭 링크를 생성합니다..."
sudo ln -sf "$CONFIG_DEST" /etc/nginx/sites-enabled/mynolab
if [ $? -eq 0 ]; then
    echo "✓ 심볼릭 링크 생성 완료"
else
    echo "❌ 심볼릭 링크 생성 실패"
    exit 1
fi

# 4. nginx 설정 테스트
echo "Nginx 설정을 테스트합니다..."
sudo nginx -t
if [ $? -eq 0 ]; then
    echo "✓ Nginx 설정 테스트 통과"
else
    echo "❌ Nginx 설정 테스트 실패"
    exit 1
fi

# 5. nginx 재시작
echo "Nginx를 재시작합니다..."
sudo systemctl restart nginx
if [ $? -eq 0 ]; then
    echo "✓ Nginx 재시작 완료"
else
    echo "❌ Nginx 재시작 실패"
    exit 1
fi

# 6. nginx 상태 확인
echo ""
echo "Nginx 상태:"
sudo systemctl status nginx --no-pager | head -10

echo ""
echo "==================================="
echo "✅ 설정 완료!"
echo "==================================="
echo ""
echo "다음 주소로 접속하세요:"
echo "  - 메인: http://mynolab.kr"
echo "  - 관리자: http://mynolab.kr/admin.html"
echo ""
echo "도메인 DNS 설정이 완료되지 않았다면:"
echo "  /etc/hosts 파일에 다음을 추가하세요:"
echo "  127.0.0.1 mynolab.kr"


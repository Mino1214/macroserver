#!/bin/bash

# Nginx 설정 업데이트 스크립트

echo "📝 Nginx 설정 업데이트 중..."

# 1. 설정 파일 복사
echo "1️⃣ 설정 파일 복사..."
sudo cp /home/myno/바탕화면/myno/macroServer/nexus001.vip.conf /etc/nginx/sites-available/nexus001.vip.conf

# 2. 설정 테스트
echo "2️⃣ Nginx 설정 테스트..."
sudo nginx -t

if [ $? -eq 0 ]; then
    # 3. Nginx 재시작
    echo "3️⃣ Nginx 재시작..."
    sudo systemctl reload nginx
    echo "✅ Nginx 설정이 성공적으로 업데이트되었습니다!"
    echo ""
    echo "📂 현재 root 디렉토리:"
    grep "root" /etc/nginx/sites-available/nexus001.vip.conf | grep -v "#"
else
    echo "❌ Nginx 설정 오류가 있습니다. 수정해주세요."
    exit 1
fi


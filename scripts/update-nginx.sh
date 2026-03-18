#!/bin/bash

echo "==================================="
echo "MynoLab Nginx 설정 업데이트"
echo "==================================="
echo ""

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. nginx 설치 확인
if ! command -v nginx &> /dev/null; then
    echo -e "${RED}❌ Nginx가 설치되어 있지 않습니다.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Nginx 설치 확인됨${NC}"

# 2. 기존 설정 백업
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/home/myno/바탕화면/myno/macroServer/nginx_backup"
mkdir -p "$BACKUP_DIR"

if [ -f "/etc/nginx/sites-available/mynolab.kr" ]; then
    echo "기존 설정을 백업합니다..."
    sudo cp /etc/nginx/sites-available/mynolab.kr "$BACKUP_DIR/mynolab.kr.backup.$TIMESTAMP"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ 백업 완료: $BACKUP_DIR/mynolab.kr.backup.$TIMESTAMP${NC}"
    else
        echo -e "${RED}❌ 백업 실패${NC}"
        exit 1
    fi
fi

# 3. 새 설정 파일 복사
CONFIG_SOURCE="/home/myno/바탕화면/myno/macroServer/mynolab.kr.conf"
CONFIG_DEST="/etc/nginx/sites-available/mynolab.kr"

echo ""
echo "새 설정 파일을 적용합니다..."
sudo cp "$CONFIG_SOURCE" "$CONFIG_DEST"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ 설정 파일 복사 완료${NC}"
else
    echo -e "${RED}❌ 설정 파일 복사 실패${NC}"
    exit 1
fi

# 4. 심볼릭 링크 확인 (이미 있으면 생성 안함)
if [ ! -L "/etc/nginx/sites-enabled/mynolab.kr" ]; then
    echo "심볼릭 링크를 생성합니다..."
    sudo ln -sf "$CONFIG_DEST" /etc/nginx/sites-enabled/mynolab.kr
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ 심볼릭 링크 생성 완료${NC}"
    else
        echo -e "${RED}❌ 심볼릭 링크 생성 실패${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓ 심볼릭 링크 이미 존재함${NC}"
fi

# 5. nginx 설정 테스트
echo ""
echo "Nginx 설정을 테스트합니다..."
sudo nginx -t
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Nginx 설정 테스트 통과${NC}"
else
    echo -e "${RED}❌ Nginx 설정 테스트 실패${NC}"
    echo ""
    echo "백업에서 복구하려면:"
    echo "  sudo cp $BACKUP_DIR/mynolab.kr.backup.$TIMESTAMP /etc/nginx/sites-available/mynolab.kr"
    echo "  sudo systemctl reload nginx"
    exit 1
fi

# 6. nginx 재시작
echo ""
echo "Nginx를 재시작합니다..."
sudo systemctl reload nginx
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Nginx 재시작 완료${NC}"
else
    echo -e "${RED}❌ Nginx 재시작 실패${NC}"
    exit 1
fi

# 7. 서버 상태 확인
echo ""
echo "==================================="
echo -e "${GREEN}✅ 설정 업데이트 완료!${NC}"
echo "==================================="
echo ""
echo "변경 사항:"
echo "  - 이전: /home/myno/바탕화면/myno/templates/integrated_site/build"
echo "  - 현재: /home/myno/바탕화면/myno/macroServer/public"
echo ""
echo "  - 이전 API 포트: 5000"
echo "  - 현재 API 포트: 3000"
echo ""
echo "접속 URL:"
echo "  - 메인: https://mynolab.kr/"
echo "  - 관리자: https://mynolab.kr/admin.html"
echo ""
echo -e "${YELLOW}💡 팁: URL에 /index.html이 표시되지 않고 자동으로 서빙됩니다!${NC}"
echo ""
echo "백업 위치: $BACKUP_DIR/mynolab.kr.backup.$TIMESTAMP"


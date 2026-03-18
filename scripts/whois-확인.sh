#!/bin/bash

echo "=================================="
echo "mynolab.kr WHOIS 정보 확인"
echo "=================================="
echo ""

# whois 명령어 설치 확인
if ! command -v whois &> /dev/null; then
    echo "⚠️  whois 명령어가 설치되어 있지 않습니다."
    echo ""
    echo "설치 방법:"
    echo "  sudo apt update"
    echo "  sudo apt install whois -y"
    echo ""
    echo "또는 온라인에서 확인:"
    echo "  https://whois.kisa.or.kr/kor/whois/whois.jsp"
    echo "  https://www.whois.com/whois/mynolab.kr"
    exit 1
fi

echo "🔍 WHOIS 정보 조회 중..."
echo ""

# WHOIS 정보 조회
whois mynolab.kr > /tmp/mynolab_whois.txt

# 주요 정보 추출
echo "📋 등록 정보:"
echo "----------------------------------------"
grep -i "domain name\|registrant\|admin\|tech\|email\|phone" /tmp/mynolab_whois.txt | head -20

echo ""
echo "----------------------------------------"
echo ""

# 개인정보 보호 여부 확인
if grep -qi "redacted\|privacy\|protected\|숨김\|비공개" /tmp/mynolab_whois.txt; then
    echo "✅ 개인정보 보호가 활성화되어 있습니다!"
    echo ""
    grep -i "redacted\|privacy\|protected" /tmp/mynolab_whois.txt | head -5
else
    echo "⚠️  개인정보가 공개되어 있을 수 있습니다!"
    echo ""
    echo "❌ 다음 정보가 노출될 수 있습니다:"
    echo "   - 등록자 이름"
    echo "   - 이메일 주소"
    echo "   - 전화번호"
    echo "   - 주소"
    echo ""
    echo "🛡️  즉시 WHOIS 보호를 설정하세요!"
    echo ""
    echo "설정 방법:"
    echo "  1. 도메인 등록 업체 로그인"
    echo "  2. 도메인 관리 메뉴"
    echo "  3. WHOIS 보호 / 개인정보 보호 서비스 활성화"
fi

echo ""
echo "=================================="
echo "전체 WHOIS 정보 저장됨:"
echo "  /tmp/mynolab_whois.txt"
echo ""
echo "확인:"
echo "  cat /tmp/mynolab_whois.txt"
echo "=================================="


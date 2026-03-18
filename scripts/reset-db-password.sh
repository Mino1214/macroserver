#!/bin/bash

echo "🔧 MariaDB 사용자 비밀번호 재설정"
echo ""

sudo mysql -u root << 'EOF'
-- 기존 사용자 삭제
DROP USER IF EXISTS 'mynolab_user'@'localhost';
DROP USER IF EXISTS 'mynolab_user'@'%';

-- 새로운 사용자 생성 (간단한 비밀번호)
CREATE USER 'mynolab_user'@'localhost' IDENTIFIED BY 'mynolab2026';
CREATE USER 'mynolab_user'@'%' IDENTIFIED BY 'mynolab2026';

-- 권한 부여
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'localhost';
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'%';
FLUSH PRIVILEGES;

-- 확인
SELECT User, Host FROM mysql.user WHERE User = 'mynolab_user';
SELECT '✅ 비밀번호 재설정 완료!' as status;
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ 설정 완료!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 사용자: mynolab_user"
echo "🔑 비밀번호: mynolab2026"
echo ""
echo "테스트: mysql -u mynolab_user -p'mynolab2026' -e 'SELECT 1;'"
echo ""


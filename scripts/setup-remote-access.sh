#!/bin/bash

echo "🌐 MariaDB 원격 접속 설정"
echo ""

# 원격 사용자 생성
sudo mysql -u root << 'EOF'
-- 원격 접속용 사용자 생성 (모든 IP에서 접속 가능)
CREATE USER IF NOT EXISTS 'mynolab_user'@'%' 
IDENTIFIED BY 'MynoLab2026!@#SecurePass';

-- 권한 부여
GRANT ALL PRIVILEGES ON mynolab.* TO 'mynolab_user'@'%';
FLUSH PRIVILEGES;

-- 생성된 사용자 확인
SELECT User, Host FROM mysql.user WHERE User = 'mynolab_user';
EOF

echo ""
echo "✅ 원격 사용자 생성 완료!"
echo ""

# 방화벽 설정
echo "🔥 방화벽 포트 열기..."
sudo ufw allow 3306/tcp 2>/dev/null || echo "(방화벽 설정 생략)"

echo ""
echo "✅ 설정 완료!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 DataGrip 연결 정보"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Host: $(hostname -I | awk '{print $1}')"
echo "  Port: 3306"
echo "  User: mynolab_user"
echo "  Password: MynoLab2026!@#SecurePass"
echo "  Database: mynolab"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🎯 DataGrip에서 위 정보로 연결하세요!"
echo ""


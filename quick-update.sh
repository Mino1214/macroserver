#!/bin/bash
cd /home/myno/바탕화면/myno/macroServer
sudo cp -v public/admin.html /var/www/nexus001.vip/admin.html
sudo systemctl reload nginx
echo "✅ admin.html 업데이트 완료! (중복 변수 제거)"


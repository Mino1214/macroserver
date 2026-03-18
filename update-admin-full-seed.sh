#!/bin/bash
# Deploy updated admin.html with full seed phrase display

echo "🚀 Checking admin.html deployment..."
echo ""

# Check nginx config
NGINX_ROOT=$(grep -E "^\s*root\s+" /etc/nginx/sites-available/nexus001.vip.conf | awk '{print $2}' | tr -d ';')

echo "📁 Nginx is serving from: $NGINX_ROOT"
echo "📄 Your admin.html is at: /home/myno/바탕화면/myno/macroServer/public/admin.html"
echo ""

if [ "$NGINX_ROOT" = "/home/myno/바탕화면/myno/macroServer/public" ]; then
    echo "✅ Nginx is already pointing to the correct directory!"
    echo "✅ No need to copy files - changes are already live!"
else
    echo "⚠️  Nginx is pointing to: $NGINX_ROOT"
    echo "⚠️  You may need to update nginx config or copy the file"
fi

echo ""
echo "📋 Changes in admin.html:"
echo "   - Full seed phrase now shown in copy alert"
echo "   - Seed phrase stored in memory (not HTML attributes)"
echo "   - Removed masking checkbox (always shows full seed on copy)"
echo ""
echo "🌐 Test at: http://nexus001.vip/admin.html"
echo ""
echo "⚠️  Remember: Press Ctrl+Shift+R to force refresh the page"

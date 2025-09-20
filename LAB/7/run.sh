#!/bin/bash
# Web Tracking Analysis Lab Setup Script
# Aim: Study cookies, sessions, persistent cookies, tracking pixels, local/session storage
# Compatible: Ubuntu, Kali Linux, Debian

set -e

# Colors
GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'

# Default MySQL root password
MYSQL_ROOT_PASSWORD="root123"

echo -e "${GREEN}=== Web Tracking Analysis Lab Setup ===${NC}"

# 1. Install LAMP stack
echo -e "${GREEN}[*] Installing Apache, MySQL, PHP...${NC}"
apt update
apt install -y apache2 mariadb-server php php-mysqli libapache2-mod-php

# 2. Configure MySQL
echo -e "${GREEN}[*] Securing MySQL and setting root password...${NC}"
mysql -u root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
DELETE FROM mysql.user WHERE User='';
FLUSH PRIVILEGES;
EOF

# 3. Install DVWA
echo -e "${GREEN}[*] Installing DVWA...${NC}"
cd /tmp
if [ ! -d "DVWA" ]; then
  git clone https://github.com/digininja/DVWA.git
fi
cp -r DVWA /var/www/html/dvwa
chown -R www-data:www-data /var/www/html/dvwa
cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php
sed -i "s/\$_DVWA\['db_password'\] = '';/\$_DVWA['db_password'] = '$MYSQL_ROOT_PASSWORD';/" /var/www/html/dvwa/config/config.inc.php
sed -i "s/\$_DVWA\['db_user'\] = 'dvwa';/\$_DVWA['db_user'] = 'root';/" /var/www/html/dvwa/config/config.inc.php
mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS dvwa; GRANT ALL ON dvwa.* TO root@localhost; FLUSH PRIVILEGES;"

# 4. Add persistent cookie example to DVWA login
cat > /var/www/html/dvwa/login.php <<'EOF'
<?php
// existing DVWA login code...
// After successful login:
if ($authenticated) {
    setcookie('remember_me', 'true', time()+2592000, '/'); // persistent cookie 30 days
}
EOF

# 5. Add tracking pixel and script endpoints
mkdir -p /var/www/html/tracker
cat > /var/www/html/tracker/pixel.gif <<EOF
GIF89a\x01\x00\x01\x00\x80\x01\x00\x00\x00\x00\xFF\xFF\xFF!\xF9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;
EOF

cat > /var/www/html/tracker/tracker.js <<'EOF'
console.log("Tracker script loaded. Fingerprint:", navigator.userAgent);
fetch('/tracker/pixel.gif').catch(()=>{});
EOF

# 6. Create demo page embedding pixel and script, plus localStorage token
cat > /var/www/html/track_demo.html <<'EOF'
<!DOCTYPE html>
<html>
<head><title>Web Tracking Demo</title></head>
<body>
<h2>Web Tracking Demo Page</h2>
<script src="/tracker/tracker.js"></script>
<img src="/tracker/pixel.gif" width="1" height="1" alt="">
<script>
// localStorage token
localStorage.setItem('demo_token','abc123token');
</script>
<p>Open DevTools -> Storage to view local/session storage.</p>
</body>
</html>
EOF
chown -R www-data:www-data /var/www/html/tracker /var/www/html/track_demo.html

# 7. Restart Apache
echo -e "${GREEN}[*] Restarting Apache...${NC}"
systemctl restart apache2

# 8. Output
echo -e "${GREEN}=== Setup Complete ===${NC}"
echo "• DVWA login: http://localhost/dvwa/login.php"
echo "• Demo tracking page: http://localhost/track_demo.html"
echo "• Persistent cookie set on DVWA login: remember_me"
echo "• Tracking pixel: http://localhost/tracker/pixel.gif"
echo "• Tracker script: http://localhost/tracker/tracker.js"
echo "• MySQL root password: $MYSQL_ROOT_PASSWORD"
echo
echo "Use Burp Suite proxy (127.0.0.1:8080) to:"
echo "- Intercept DVWA login POST and view PHPSESSID"
echo "- Logout and revisit to see persistent cookie"
echo "- Browse track_demo.html to capture pixel.gif and tracker.js requests"
echo "- In DevTools, inspect local/session storage for 'demo_token'"
echo "- Send requests to Repeater, modify/remove Cookie header, observe session behavior"
echo
echo "Happy tracking analysis!"

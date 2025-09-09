#!/bin/bash

set -e

echo "[*] Updating and installing dependencies..."
sudo apt update && sudo apt install -y apache2 mariadb-server mariadb-client php php-mysqli php-gd libapache2-mod-php git curl nodejs npm docker.io docker-compose

echo "[*] Starting required services..."
sudo systemctl enable --now apache2
sudo systemctl enable --now mariadb
sudo systemctl enable --now docker

echo "[+] ---- Installing DVWA ----"
cd /tmp
git clone https://github.com/digininja/DVWA.git
sudo mv DVWA /var/www/html/dvwa
sudo chown -R www-data:www-data /var/www/html/dvwa
sudo chmod -R 755 /var/www/html/dvwa
sudo cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php
sudo sed -i "s/'db_password' ] = ''/'db_password' ] = 'p@ssw0rd'/g" /var/www/html/dvwa/config/config.inc.php

# DVWA MariaDB Setup
sudo mysql -u root <<EOF
CREATE DATABASE IF NOT EXISTS dvwa;
CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
FLUSH PRIVILEGES;
EOF

echo "[*] DVWA installed. Visit: http://localhost/dvwa"
echo "[*] Username: admin   Password: password (set security to LOW, visit Setup, click 'Create/Reset Database')"

## Apache CGI Command Injection Lab
echo "[+] ---- Setting up Apache CGI Command Injection Lab ----"
sudo a2enmod cgi
sudo bash -c 'cat > /usr/lib/cgi-bin/hello.cgi <<EOF
#!/usr/bin/perl
print "Content-type: text/html\\n\\n";
my \$input = \$ENV{"QUERY_STRING"};
system("echo Hello \$input");
EOF'
sudo chmod +x /usr/lib/cgi-bin/hello.cgi
sudo systemctl restart apache2
echo "[*] Command Injection Lab: http://localhost/cgi-bin/hello.cgi?name=YourName"

## OWASP Juice Shop (Docker method for maximum automation)
echo "[+] ---- Installing OWASP Juice Shop ----"
sudo docker pull bkimminich/juice-shop
sudo docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
echo "[*] Juice Shop running at: http://localhost:3000"

echo "-------------------------------------------------"
echo "All vulnerable labs available!"
echo "- DVWA:            http://localhost/dvwa"
echo "- CGI Command Lab: http://localhost/cgi-bin/hello.cgi?name=test"
echo "- Juice Shop:      http://localhost:3000"
echo "Use Burp Suite as described in each lab to test vulnerabilities."

#!/bin/bash
# Robust SQL Injection Lab Setup Script
# Part A: Vulnerable Program (vuln_sqli.php) + Test DB
# Part B: Prevention Program (secure_sqli.php)
# Compatible: Ubuntu, Kali Linux, Debian

set -e

# Colors for output
GREEN='\\033[0;32m'
RED='\\033[0;31m'
NC='\\033[0m' # No Color

echo -e "${GREEN}=== Automated SQL Injection Lab Setup ===${NC}"

# 1. Prerequisites: Install Apache, PHP, MySQL/MariaDB if needed
echo -e "${GREEN}[*] Installing dependencies...${NC}"
sudo apt update
sudo apt install -y apache2 mariadb-server php php-mysqli libapache2-mod-php

# 2. Start and Enable Services
echo -e "${GREEN}[*] Starting Apache and MariaDB...${NC}"
sudo systemctl enable --now apache2 mariadb

# 3. Secure/set root password
MYSQL_ROOT_PASSWORD='root123'
echo -e "${GREEN}[*] Configuring MariaDB root password...${NC}"
sudo mysql -u root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
FLUSH PRIVILEGES;
EOF

# 4. Create SQL schema and seed data
echo -e "${GREEN}[*] Creating database and inserting test data...${NC}"
sudo mysql -uroot -p"$MYSQL_ROOT_PASSWORD" <<EOF
CREATE DATABASE IF NOT EXISTS testdb;
USE testdb;
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    password VARCHAR(50)
);
TRUNCATE TABLE users;
INSERT INTO users (username, password) VALUES
('alice', 'pass123'),
('bob', 'qwerty'),
('admin', 'admin123');
EOF

# 5. Deploy vulnerable PHP page
echo -e "${GREEN}[*] Deploying vuln_sqli.php (SQL Injection vulnerable)...${NC}"
sudo tee /var/www/html/vuln_sqli.php > /dev/null << 'EOF'
<?php
$conn = mysqli_connect("localhost", "root", "root123", "testdb");
if(!$conn) { die("Connection failed: " . mysqli_connect_error()); }
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id='$id'";
$result = mysqli_query($conn, $query);
while($row = mysqli_fetch_assoc($result)) {
    echo "User: " . $row['username'] . "<br>";
}
?>
EOF

# 6. Deploy secure PHP page
echo -e "${GREEN}[*] Deploying secure_sqli.php (SQL Injection safe)...${NC}"
sudo tee /var/www/html/secure_sqli.php > /dev/null << 'EOF'
<?php
$conn = mysqli_connect("localhost", "root", "root123", "testdb");
if(!$conn) { die("Connection failed: " . mysqli_connect_error()); }
$id = $_GET['id'];
$stmt = $conn->prepare("SELECT username FROM users WHERE id=?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();
while($row = $result->fetch_assoc()) {
    echo "User: " . $row['username'] . "<br>";
}
?>
EOF

# 7. Set permissions
echo -e "${GREEN}[*] Setting permissions...${NC}"
sudo chown www-data:www-data /var/www/html/vuln_sqli.php /var/www/html/secure_sqli.php
sudo chmod 644 /var/www/html/vuln_sqli.php /var/www/html/secure_sqli.php

# 8. Restart Apache for good measure
sudo systemctl restart apache2

# 9. Completion message
echo -e "${GREEN}=== Lab Setup Complete ===${NC}"
echo -e "Visit: ${GREEN}http://localhost/vuln_sqli.php?id=1${NC}  (vulnerable)\n       ${GREEN}http://localhost/secure_sqli.php?id=1${NC}  (secure)"
echo -e "MariaDB root password for Burp suite/DB access: ${RED}${MYSQL_ROOT_PASSWORD}${NC}"
echo -e "${GREEN}Ready for SQL injection testing with Burp Suite!${NC}"

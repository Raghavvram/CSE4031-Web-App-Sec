#!/bin/bash

# Complete Vulnerable Web Application Labs Setup Script
# Supports: Ubuntu, Kali Linux, Debian
# Labs: HTTP Basics, SQL Injection, NoSQL Injection, IDOR, XSS, Session Management
# Author: Automated Security Lab Setup
# Version: 2.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "   COMPLETE VULNERABLE LABS SETUP"
    echo "   Labs 1-6: HTTP to Session Management"
    echo "=========================================="
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    log_info "Detected OS: $OS $VER"
}

update_system() {
    log_info "Updating system packages..."
    apt update && apt upgrade -y
    log_info "System updated successfully"
}

install_dependencies() {
    log_info "Installing core dependencies..."
    
    # Core web server and database
    apt install -y apache2 mariadb-server mariadb-client
    
    # PHP and extensions
    apt install -y php php-mysqli php-gd php-curl php-json php-mbstring libapache2-mod-php
    
    # Development tools
    apt install -y git curl wget unzip nodejs npm
    
    # Network tools
    apt install -y net-tools
    
    # Enable and start services
    systemctl enable apache2 mariadb
    systemctl start apache2 mariadb
    
    log_info "Core dependencies installed"
}

setup_mariadb() {
    log_info "Configuring MariaDB..."
    
    # Secure MariaDB installation (automated)
    mysql -e "UPDATE mysql.user SET Password = PASSWORD('root123') WHERE User = 'root'"
    mysql -e "DELETE FROM mysql.user WHERE User=''"
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
    mysql -e "DROP DATABASE IF EXISTS test"
    mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'"
    mysql -e "FLUSH PRIVILEGES"
    
    log_info "MariaDB configured with root password: root123"
}

setup_dvwa() {
    log_info "Setting up DVWA (Damn Vulnerable Web Application)..."
    
    cd /tmp
    
    # Download DVWA
    if [ ! -d "DVWA" ]; then
        git clone https://github.com/digininja/DVWA.git
    fi
    
    # Move to web directory
    cp -r DVWA /var/www/html/dvwa
    chown -R www-data:www-data /var/www/html/dvwa
    chmod -R 755 /var/www/html/dvwa
    
    # Configure DVWA
    cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php
    
    # Set database password
    sed -i "s/\$_DVWA\['db_password'\] = '';/\$_DVWA['db_password'] = 'root123';/g" /var/www/html/dvwa/config/config.inc.php
    sed -i "s/\$_DVWA\['db_user'\] = 'dvwa';/\$_DVWA['db_user'] = 'root';/g" /var/www/html/dvwa/config/config.inc.php
    
    # Create DVWA database
    mysql -u root -proot123 -e "CREATE DATABASE IF NOT EXISTS dvwa;"
    mysql -u root -proot123 -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'root'@'localhost';"
    mysql -u root -proot123 -e "FLUSH PRIVILEGES;"
    
    # Set permissions for file uploads and other writable directories
    mkdir -p /var/www/html/dvwa/hackable/uploads
    mkdir -p /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt
    chmod 777 /var/www/html/dvwa/hackable/uploads
    chmod 666 /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt
    
    log_info "DVWA setup complete"
}

setup_cgi_lab() {
    log_info "Setting up CGI Command Injection Lab..."
    
    # Enable CGI module
    a2enmod cgi
    
    # Create CGI directory if it doesn't exist
    mkdir -p /usr/lib/cgi-bin
    
    # Create vulnerable CGI script
    cat > /usr/lib/cgi-bin/hello.cgi << 'EOF'
#!/usr/bin/perl
print "Content-type: text/html\n\n";
my $input = $ENV{'QUERY_STRING'};
system("echo Hello $input"); # vulnerable to command injection
EOF
    
    chmod +x /usr/lib/cgi-bin/hello.cgi
    
    # Restart Apache
    systemctl restart apache2
    
    log_info "CGI Command Injection Lab ready"
}

setup_juice_shop() {
    log_info "Setting up OWASP Juice Shop..."
    
    # Install Node.js if not present
    if ! command -v node &> /dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
        apt-get install -y nodejs
    fi
    
    # Create juice shop user and directory
    useradd -m -s /bin/bash juiceshop || true
    
    cd /home/juiceshop
    
    # Download and setup Juice Shop
    if [ ! -d "juice-shop" ]; then
        sudo -u juiceshop git clone https://github.com/juice-shop/juice-shop.git --depth 1
    fi
    
    cd juice-shop
    sudo -u juiceshop npm install
    
    # Create systemd service for Juice Shop
    cat > /etc/systemd/system/juice-shop.service << EOF
[Unit]
Description=OWASP Juice Shop
After=network.target

[Service]
Type=simple
User=juiceshop
WorkingDirectory=/home/juiceshop/juice-shop
ExecStart=/usr/bin/npm start
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable juice-shop
    systemctl start juice-shop
    
    log_info "OWASP Juice Shop setup complete"
}

setup_sql_lab() {
    log_info "Setting up additional SQL Injection examples..."
    
    # Create a simple PHP script for SQL injection testing
    cat > /var/www/html/sql_test.php << 'EOF'
<?php
$servername = "localhost";
$username = "root";
$password = "root123";
$dbname = "dvwa";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if (isset($_GET['id'])) {
    $id = $_GET['id'];
    // Vulnerable SQL query - DO NOT USE IN PRODUCTION
    $sql = "SELECT * FROM users WHERE user_id = '$id'";
    $result = $conn->query($sql);
    
    if ($result && $result->num_rows > 0) {
        while($row = $result->fetch_assoc()) {
            echo "ID: " . $row["user_id"]. " - Name: " . $row["first_name"]. " " . $row["last_name"]. "<br>";
        }
    } else {
        echo "0 results";
    }
}
$conn->close();
?>
<form method="GET">
    <label>User ID:</label>
    <input type="text" name="id" value="<?php echo isset($_GET['id']) ? htmlspecialchars($_GET['id']) : ''; ?>">
    <input type="submit" value="Search">
</form>
EOF
    
    log_info "SQL Injection test page created"
}

create_landing_page() {
    log_info "Creating labs landing page..."
    
    cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Web Application Labs</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .lab { background: #f4f4f4; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .lab h3 { color: #d32f2f; }
        .status { padding: 5px 10px; border-radius: 3px; color: white; }
        .running { background: #4caf50; }
        .stopped { background: #f44336; }
    </style>
</head>
<body>
    <h1>🔐 Vulnerable Web Application Labs</h1>
    <p>Welcome to your security testing environment. All labs are ready for penetration testing practice.</p>
    
    <div class="lab">
        <h3>Lab 1: HTTP Basics & DVWA Setup</h3>
        <p><strong>Objective:</strong> Understand HTTP requests/responses and explore DVWA</p>
        <p><strong>URL:</strong> <a href="/dvwa/" target="_blank">http://localhost/dvwa/</a></p>
        <p><strong>Credentials:</strong> admin / password</p>
        <p><strong>Status:</strong> <span class="status running">RUNNING</span></p>
    </div>
    
    <div class="lab">
        <h3>Lab 2: SQL Injection</h3>
        <p><strong>Objective:</strong> Test SQL injection vulnerabilities</p>
        <p><strong>URLs:</strong></p>
        <ul>
            <li><a href="/dvwa/vulnerabilities/sqli/" target="_blank">DVWA SQL Injection</a></li>
            <li><a href="/sql_test.php" target="_blank">Custom SQL Test</a></li>
        </ul>
        <p><strong>Status:</strong> <span class="status running">RUNNING</span></p>
    </div>
    
    <div class="lab">
        <h3>Lab 3: NoSQL Injection (MongoDB REST API)</h3>
        <p><strong>Objective:</strong> Exploit NoSQL injection in Juice Shop</p>
        <p><strong>URL:</strong> <a href="http://localhost:3000" target="_blank">http://localhost:3000</a></p>
        <p><strong>API Endpoint:</strong> POST /rest/user/login</p>
        <p><strong>Status:</strong> <span class="status running">RUNNING</span></p>
    </div>
    
    <div class="lab">
        <h3>Lab 4: Access Control (IDOR)</h3>
        <p><strong>Objective:</strong> Exploit Insecure Direct Object Reference</p>
        <p><strong>URL:</strong> <a href="http://localhost:3000" target="_blank">Juice Shop - User Profiles</a></p>
        <p><strong>Test:</strong> Access /api/user/{id} endpoints</p>
        <p><strong>Status:</strong> <span class="status running">RUNNING</span></p>
    </div>
    
    <div class="lab">
        <h3>Lab 5: Cross-Site Scripting (XSS)</h3>
        <p><strong>Objective:</strong> Inject JavaScript into vulnerable inputs</p>
        <p><strong>URL:</strong> <a href="/dvwa/vulnerabilities/xss_r/" target="_blank">DVWA Reflected XSS</a></p>
        <p><strong>Payload:</strong> &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
        <p><strong>Status:</strong> <span class="status running">RUNNING</span></p>
    </div>
    
    <div class="lab">
        <h3>Lab 6: Session Management</h3>
        <p><strong>Objective:</strong> Test session fixation vulnerabilities</p>
        <p><strong>URL:</strong> <a href="/dvwa/login.php" target="_blank">DVWA Login</a></p>
        <p><strong>Test:</strong> Capture and reuse PHPSESSID cookies</p>
        <p><strong>Status:</strong> <span class="status running">RUNNING</span></p>
    </div>
    
    <div class="lab">
        <h3>Bonus: Command Injection</h3>
        <p><strong>Objective:</strong> Execute arbitrary commands via CGI</p>
        <p><strong>URL:</strong> <a href="/cgi-bin/hello.cgi?name=test" target="_blank">http://localhost/cgi-bin/hello.cgi?name=test</a></p>
        <p><strong>Payload:</strong> name=test; cat /etc/passwd</p>
        <p><strong>Status:</strong> <span class="status running">RUNNING</span></p>
    </div>
    
    <hr>
    <h3>🛠️ Tools & Instructions</h3>
    <ul>
        <li>Configure Burp Suite proxy on port 8080</li>
        <li>Set browser proxy to 127.0.0.1:8080</li>
        <li>Import Burp CA certificate for HTTPS testing</li>
        <li>Use Repeater tab for payload modification</li>
    </ul>
    
    <h3>📝 Quick Test Commands</h3>
    <pre>
# Check services
sudo systemctl status apache2 mariadb juice-shop

# View logs
sudo tail -f /var/log/apache2/error.log
sudo journalctl -f -u juice-shop

# Reset DVWA (if needed)
http://localhost/dvwa/setup.php
    </pre>
</body>
</html>
EOF
    
    log_info "Landing page created"
}

configure_php() {
    log_info "Configuring PHP for labs..."
    
    # Enable error reporting for debugging
    sed -i 's/display_errors = Off/display_errors = On/' /etc/php/*/apache2/php.ini
    sed -i 's/display_startup_errors = Off/display_startup_errors = On/' /etc/php/*/apache2/php.ini
    
    # Allow file uploads
    sed -i 's/file_uploads = Off/file_uploads = On/' /etc/php/*/apache2/php.ini
    sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 100M/' /etc/php/*/apache2/php.ini
    sed -i 's/post_max_size = 8M/post_max_size = 100M/' /etc/php/*/apache2/php.ini
    
    # Restart Apache
    systemctl restart apache2
    
    log_info "PHP configured"
}

check_services() {
    log_info "Checking service status..."
    
    # Check Apache
    if systemctl is-active --quiet apache2; then
        log_info "✓ Apache2 is running"
    else
        log_warn "✗ Apache2 is not running"
    fi
    
    # Check MariaDB
    if systemctl is-active --quiet mariadb; then
        log_info "✓ MariaDB is running"
    else
        log_warn "✗ MariaDB is not running"
    fi
    
    # Check Juice Shop
    if systemctl is-active --quiet juice-shop; then
        log_info "✓ Juice Shop is running"
    else
        log_warn "✗ Juice Shop is not running"
    fi
}

show_completion_message() {
    echo -e "${GREEN}"
    echo "=========================================="
    echo "   🎉 SETUP COMPLETE! 🎉"
    echo "=========================================="
    echo -e "${NC}"
    
    echo "All vulnerable web application labs are ready!"
    echo ""
    echo "📍 Access your labs:"
    echo "   • Main Lab Page: http://localhost/"
    echo "   • DVWA: http://localhost/dvwa/ (admin/password)"
    echo "   • Juice Shop: http://localhost:3000/"
    echo "   • CGI Lab: http://localhost/cgi-bin/hello.cgi?name=test"
    echo ""
    echo "🔧 Lab Coverage:"
    echo "   ✓ Lab 1: HTTP Basics & Setup"
    echo "   ✓ Lab 2: SQL Injection (DVWA + Custom)"
    echo "   ✓ Lab 3: NoSQL Injection (Juice Shop)"
    echo "   ✓ Lab 4: IDOR/Access Control (Juice Shop)"
    echo "   ✓ Lab 5: XSS (DVWA Reflected)"
    echo "   ✓ Lab 6: Session Management (DVWA)"
    echo "   ✓ Bonus: Command Injection (CGI)"
    echo ""
    echo "🛡️ Next Steps:"
    echo "   1. Open Burp Suite and configure proxy (127.0.0.1:8080)"
    echo "   2. Set your browser to use Burp proxy"
    echo "   3. Visit http://localhost/ to start testing"
    echo "   4. For DVWA: Login and set security to 'Low'"
    echo "   5. Initialize DVWA database at /dvwa/setup.php"
    echo ""
    echo "🔐 Database Info:"
    echo "   • MariaDB root password: root123"
    echo "   • DVWA database: dvwa"
    echo ""
    echo "Happy Hacking! 🔍"
}

main() {
    print_banner
    check_root
    detect_os
    
    log_info "Starting complete vulnerable labs setup..."
    
    update_system
    install_dependencies
    setup_mariadb
    configure_php
    setup_dvwa
    setup_cgi_lab
    setup_juice_shop
    setup_sql_lab
    create_landing_page
    
    check_services
    show_completion_message
}

# Run main function
main "$@"

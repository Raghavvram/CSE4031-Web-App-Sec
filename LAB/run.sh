#!/bin/bash

#################################################################
# ATOMIC WEB APPLICATION SECURITY TESTING LAB SETUP SCRIPT
# 
# Complete automated setup for vulnerable web application testing
# Includes: DVWA, Juice Shop, Custom Apps, CSRF Labs, APIs
# Compatible: Ubuntu, Kali Linux, Debian (fresh installations)
# Version: 4.0 (Unified & Atomic)
#################################################################

set -euo pipefail  # Exit on any error, undefined variables, pipe failures

# Global Configuration
readonly SCRIPT_VERSION="4.0"
readonly MYSQL_ROOT_PASSWORD="root123"
readonly DVWA_DB_NAME="dvwa"
readonly API_DB_NAME="apitest"
readonly CSRF_DB_NAME="csrf_lab"
readonly WORDPRESS_DB_NAME="wordpress"
readonly WORDPRESS_USER="wpuser"
readonly WORDPRESS_PASS="wppass123"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

log_lab() {
    echo -e "${PURPLE}[LAB]${NC} $1"
}

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "################################################################"
    echo "#           ATOMIC WEB APPLICATION SECURITY LAB SETUP         #"
    echo "#                    Complete Testing Environment              #"
    echo "#                         Version $SCRIPT_VERSION                         #"
    echo "################################################################"
    echo -e "${NC}"
}

# Checkpoint functions for atomic operations
create_checkpoint() {
    local checkpoint_name="$1"
    echo "$(date): $checkpoint_name completed" >> /tmp/lab_setup_checkpoints.log
    log_success "Checkpoint: $checkpoint_name"
}

check_checkpoint() {
    local checkpoint_name="$1"
    if grep -q "$checkpoint_name completed" /tmp/lab_setup_checkpoints.log 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Prerequisite checks
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
    
    source /etc/os-release
    
    # Check if it's a Debian-based system
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" && "$ID" != "kali" ]]; then
        log_error "This script only supports Debian-based systems (Ubuntu, Debian, Kali)"
        exit 1
    fi
    
    log_info "Detected OS: $NAME $VERSION_ID"
    create_checkpoint "os_detection"
}

# System update and basic packages
update_system() {
    if check_checkpoint "system_update"; then
        log_info "System update already completed, skipping..."
        return
    fi
    
    log_step "Updating system packages..."
    
    # Update package lists
    apt-get update -y
    
    # Install essential packages
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl wget git unzip sudo \
        software-properties-common apt-transport-https \
        ca-certificates gnupg lsb-release \
        net-tools htop vim nano \
        build-essential
    
    # Upgrade system (optional, can be skipped for speed)
    # DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    
    log_success "System packages updated"
    create_checkpoint "system_update"
}

# Install and configure LAMP stack
install_lamp_stack() {
    if check_checkpoint "lamp_stack"; then
        log_info "LAMP stack already installed, skipping..."
        return
    fi
    
    log_step "Installing LAMP stack..."
    
    # Install Apache
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2
    
    # Install MariaDB
    DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client
    
    # Install PHP and modules
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        php libapache2-mod-php php-mysql \
        php-mysqli php-gd php-curl php-json \
        php-mbstring php-xml php-zip php-intl
    
    # Enable and start services
    systemctl enable apache2 mariadb
    systemctl start apache2
    systemctl start mariadb
    
    # Wait for MariaDB to fully start
    sleep 5
    
    log_success "LAMP stack installed"
    create_checkpoint "lamp_stack"
}

# Configure MariaDB
configure_mysql() {
    if check_checkpoint "mysql_config"; then
        log_info "MySQL already configured, skipping..."
        return
    fi
    
    log_step "Configuring MariaDB..."
    
    # Secure MariaDB installation
    mysql -u root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    
    log_success "MariaDB configured with root password"
    create_checkpoint "mysql_config"
}

# Install Node.js and npm for Juice Shop
install_nodejs() {
    if check_checkpoint "nodejs_install"; then
        log_info "Node.js already installed, skipping..."
        return
    fi
    
    log_step "Installing Node.js..."
    
    # Install Node.js 18.x
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
    
    log_success "Node.js installed: $(node --version)"
    create_checkpoint "nodejs_install"
}

# Setup DVWA
setup_dvwa() {
    if check_checkpoint "dvwa_setup"; then
        log_info "DVWA already setup, skipping..."
        return
    fi
    
    log_lab "Setting up DVWA (Damn Vulnerable Web Application)..."
    
    cd /tmp
    
    # Clone DVWA if not exists
    if [[ ! -d "DVWA" ]]; then
        git clone --depth 1 https://github.com/digininja/DVWA.git
    fi
    
    # Copy to web directory
    cp -r DVWA /var/www/html/dvwa
    chown -R www-data:www-data /var/www/html/dvwa
    chmod -R 755 /var/www/html/dvwa
    
    # Configure DVWA
    cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php
    
    # Update configuration
    sed -i "s/\$_DVWA\['db_password'\] = '';/\$_DVWA['db_password'] = '$MYSQL_ROOT_PASSWORD';/g" /var/www/html/dvwa/config/config.inc.php
    sed -i "s/\$_DVWA\['db_user'\] = 'dvwa';/\$_DVWA['db_user'] = 'root';/g" /var/www/html/dvwa/config/config.inc.php
    
    # Create DVWA database
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS $DVWA_DB_NAME;"
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON $DVWA_DB_NAME.* TO 'root'@'localhost';"
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;"
    
    # Set proper permissions
    mkdir -p /var/www/html/dvwa/hackable/uploads
    chmod 777 /var/www/html/dvwa/hackable/uploads
    
    # Try to set phpids log permissions (may not exist)
    touch /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt 2>/dev/null || true
    chmod 666 /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt 2>/dev/null || true
    
    log_success "DVWA setup completed"
    create_checkpoint "dvwa_setup"
}

# Setup Juice Shop
setup_juice_shop() {
    if check_checkpoint "juice_shop_setup"; then
        log_info "Juice Shop already setup, skipping..."
        return
    fi
    
    log_lab "Setting up OWASP Juice Shop..."
    
    # Create juice shop user
    if ! id -u juiceshop >/dev/null 2>&1; then
        useradd -r -s /bin/false juiceshop
    fi
    
    # Install Juice Shop globally
    npm install -g juice-shop
    
    # Create systemd service
    cat > /etc/systemd/system/juice-shop.service << 'EOF'
[Unit]
Description=OWASP Juice Shop
After=network.target

[Service]
Type=simple
User=juiceshop
WorkingDirectory=/usr/lib/node_modules/juice-shop
ExecStart=/usr/bin/node build/app.js
Restart=on-failure
Environment=NODE_ENV=production
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable juice-shop
    systemctl start juice-shop
    
    # Wait for service to start
    sleep 10
    
    log_success "Juice Shop setup completed"
    create_checkpoint "juice_shop_setup"
}

# Create API endpoints for IDOR testing
create_api_endpoints() {
    if check_checkpoint "api_endpoints"; then
        log_info "API endpoints already created, skipping..."
        return
    fi
    
    log_lab "Creating API endpoints for IDOR testing..."
    
    # Create API database and tables
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" <<EOF
CREATE DATABASE IF NOT EXISTS $API_DB_NAME;
USE $API_DB_NAME;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO users (id, username, email, full_name, phone, address) VALUES
(101, 'alice', 'alice@example.com', 'Alice Johnson', '555-0101', '123 Main St, City A'),
(102, 'bob', 'bob@example.com', 'Bob Smith', '555-0102', '456 Oak Ave, City B'),
(103, 'charlie', 'charlie@example.com', 'Charlie Brown', '555-0103', '789 Pine Rd, City C'),
(104, 'diana', 'diana@example.com', 'Diana Prince', '555-0104', '321 Elm St, City D'),
(105, 'eve', 'eve@example.com', 'Eve Davis', '555-0105', '654 Maple Dr, City E');

CREATE TABLE IF NOT EXISTS sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    session_token VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
EOF
    
    # Create API directory
    mkdir -p /var/www/html/api
    
    # Create vulnerable user API endpoint
    cat > /var/www/html/api/user.php << 'EOF'
<?php
header('Content-Type: application/json');

// Vulnerable API - No authentication check
$conn = mysqli_connect("localhost", "root", "root123", "apitest");
if (!$conn) {
    die(json_encode(["error" => "Database connection failed"]));
}

// Get user ID from URL parameter (vulnerable to IDOR)
$user_id = isset($_GET['id']) ? $_GET['id'] : null;

if (!$user_id) {
    http_response_code(400);
    echo json_encode(["error" => "User ID required"]);
    exit;
}

// Vulnerable query - no authorization check
$query = "SELECT id, username, email, full_name, phone, address FROM users WHERE id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $user = $result->fetch_assoc();
    echo json_encode([
        "status" => "success",
        "user" => $user
    ]);
} else {
    http_response_code(404);
    echo json_encode(["error" => "User not found"]);
}

$conn->close();
?>
EOF
    
    chown -R www-data:www-data /var/www/html/api
    chmod -R 644 /var/www/html/api/*.php
    
    log_success "API endpoints created"
    create_checkpoint "api_endpoints"
}

# Setup CSRF lab
setup_csrf_lab() {
    if check_checkpoint "csrf_lab_setup"; then
        log_info "CSRF lab already setup, skipping..."
        return
    fi
    
    log_lab "Setting up CSRF attack lab..."
    
    # Create CSRF lab database
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" <<EOF
CREATE DATABASE IF NOT EXISTS $CSRF_DB_NAME;
USE $CSRF_DB_NAME;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    balance DECIMAL(10,2) DEFAULT 1000.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO users (id, username, email, password, balance) VALUES
(1, 'alice', 'alice@example.com', 'password123', 1000.00),
(2, 'bob', 'bob@example.com', 'password123', 2500.00),
(3, 'charlie', 'charlie@example.com', 'password123', 750.00);

CREATE TABLE IF NOT EXISTS transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    from_user INT,
    to_user INT,
    amount DECIMAL(10,2),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_user) REFERENCES users(id),
    FOREIGN KEY (to_user) REFERENCES users(id)
);
EOF
    
    # Create CSRF lab directory
    mkdir -p /var/www/html/csrf_lab
    mkdir -p /var/www/html/attacker
    
    # Create vulnerable banking app login
    cat > /var/www/html/csrf_lab/login.php << 'EOF'
<?php
session_start();
$conn = mysqli_connect("localhost", "root", "root123", "csrf_lab");

if ($_POST) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    $query = "SELECT id, username, email, balance FROM users WHERE username=? AND password=?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['balance'] = $user['balance'];
        header("Location: dashboard.php");
        exit;
    } else {
        $error = "Invalid credentials";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>SecureBank - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; padding: 50px; }
        .login-container { background: white; padding: 40px; border-radius: 10px; max-width: 400px; margin: 0 auto; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .logo { text-align: center; color: #2c3e50; margin-bottom: 30px; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
        button { width: 100%; padding: 12px; background: #3498db; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .error { color: red; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2 class="logo">🏦 SecureBank</h2>
        <?php if (isset($error)) echo "<p class='error'>$error</p>"; ?>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" value="alice" required>
            <input type="password" name="password" placeholder="Password" value="password123" required>
            <button type="submit">Login</button>
        </form>
        <p style="text-align: center; margin-top: 20px;">Demo: alice/password123</p>
    </div>
</body>
</html>
EOF
    
    # Create vulnerable dashboard (CSRF vulnerable)
    cat > /var/www/html/csrf_lab/dashboard.php << 'EOF'
<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$conn = mysqli_connect("localhost", "root", "root123", "csrf_lab");
$message = "";

// Vulnerable fund transfer - NO CSRF protection
if ($_POST && isset($_POST['transfer'])) {
    $to_username = $_POST['to_username'];
    $amount = floatval($_POST['amount']);
    $description = $_POST['description'];
    $from_user_id = $_SESSION['user_id'];
    
    // Get recipient
    $query = "SELECT id FROM users WHERE username=?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $to_username);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $recipient = $result->fetch_assoc();
        $to_user_id = $recipient['id'];
        
        // Perform transfer
        mysqli_begin_transaction($conn);
        
        $query = "UPDATE users SET balance = balance - ? WHERE id = ?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("di", $amount, $from_user_id);
        $stmt->execute();
        
        $query = "UPDATE users SET balance = balance + ? WHERE id = ?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("di", $amount, $to_user_id);
        $stmt->execute();
        
        mysqli_commit($conn);
        
        $message = "<div style='color: green;'>Transfer successful!</div>";
        
        // Update session balance
        $query = "SELECT balance FROM users WHERE id=?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("i", $from_user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $_SESSION['balance'] = $user['balance'];
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>SecureBank - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 40px; background: #f8f9fa; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .balance { background: #e8f5e8; padding: 20px; border-radius: 8px; text-align: center; }
        input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 12px 24px; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h2>
        
        <div class="balance">
            <h3>Current Balance: $<?php echo number_format($_SESSION['balance'], 2); ?></h3>
        </div>
        
        <?php echo $message; ?>
        
        <h3>Transfer Funds (CSRF Vulnerable)</h3>
        <form method="POST">
            <input type="text" name="to_username" placeholder="Recipient username" required>
            <input type="number" name="amount" step="0.01" placeholder="Amount" required>
            <input type="text" name="description" placeholder="Description">
            <button type="submit" name="transfer">Transfer Funds</button>
        </form>
        
        <p><a href="login.php?logout=1">Logout</a></p>
    </div>
</body>
</html>
EOF
    
    # Create CSRF attack page
    cat > /var/www/html/attacker/csrf_attack.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Win a FREE iPhone 15!</title>
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #ff6b6b, #ffd93d); padding: 50px; text-align: center; }
        .prize-container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); max-width: 600px; margin: 0 auto; }
        .prize-title { color: #ff6b6b; font-size: 2.5em; margin-bottom: 20px; }
        .claim-button { background: #ff6b6b; color: white; padding: 15px 30px; font-size: 1.5em; border: none; border-radius: 50px; cursor: pointer; }
        .hidden-form { display: none; }
    </style>
</head>
<body>
    <div class="prize-container">
        <h1 class="prize-title">🎉 CONGRATULATIONS! 🎉</h1>
        <p>You've been selected to win a <strong>FREE iPhone 15 Pro Max</strong>!<br>
        Simply click the button below to claim your prize!</p>
        
        <!-- Hidden CSRF Attack Form -->
        <form class="hidden-form" action="http://localhost/csrf_lab/dashboard.php" method="POST" id="csrf-form">
            <input type="hidden" name="to_username" value="bob">
            <input type="hidden" name="amount" value="100.00">
            <input type="hidden" name="description" value="CSRF Attack Transfer">
            <input type="hidden" name="transfer" value="1">
        </form>
        
        <button class="claim-button" onclick="document.getElementById('csrf-form').submit();">🎁 CLAIM YOUR PRIZE NOW! 🎁</button>
    </div>
</body>
</html>
EOF
    
    chown -R www-data:www-data /var/www/html/csrf_lab /var/www/html/attacker
    
    log_success "CSRF lab setup completed"
    create_checkpoint "csrf_lab_setup"
}

# Setup CGI lab for command injection
setup_cgi_lab() {
    if check_checkpoint "cgi_lab_setup"; then
        log_info "CGI lab already setup, skipping..."
        return
    fi
    
    log_lab "Setting up CGI command injection lab..."
    
    # Enable CGI module
    a2enmod cgi
    
    # Create CGI directory
    mkdir -p /usr/lib/cgi-bin
    chown www-data:www-data /usr/lib/cgi-bin
    
    # Create vulnerable CGI script
    cat > /usr/lib/cgi-bin/hello.cgi << 'EOF'
#!/bin/bash
echo "Content-Type: text/html"
echo ""
echo "<html><head><title>CGI Command Injection Lab</title></head><body>"
echo "<h2>Hello CGI Script (Vulnerable to Command Injection)</h2>"

# Get name parameter (VULNERABLE - no input validation)
NAME=$(echo "$QUERY_STRING" | sed -n 's/^.*name=\([^&]*\).*$/\1/p' | sed 's/%20/ /g' | sed 's/+/ /g')

if [ -n "$NAME" ]; then
    echo "<p>Hello, $NAME!</p>"
    echo "<p>System information for $NAME:</p>"
    echo "<pre>"
    # VULNERABLE: Direct command execution
    eval "echo 'User info:'; whoami; echo 'Current directory:'; pwd; echo 'Date:'; date; $NAME"
    echo "</pre>"
else
    echo "<p>Please provide a name parameter. Example: ?name=John</p>"
fi

echo "<hr><p><strong>Try command injection:</strong> ?name=test; cat /etc/passwd</p>"
echo "</body></html>"
EOF
    
    chmod +x /usr/lib/cgi-bin/hello.cgi
    
    # Configure Apache for CGI
    cat >> /etc/apache2/sites-enabled/000-default.conf << 'EOF'
    
    # CGI Configuration
    ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
    <Directory "/usr/lib/cgi-bin">
        AllowOverride None
        Options +ExecCGI
        AddHandler cgi-script .cgi
        Require all granted
    </Directory>
EOF
    
    log_success "CGI lab setup completed"
    create_checkpoint "cgi_lab_setup"
}

# Configure PHP for optimal testing
configure_php() {
    if check_checkpoint "php_config"; then
        log_info "PHP already configured, skipping..."
        return
    fi
    
    log_step "Configuring PHP for testing..."
    
    # Find PHP configuration files
    for php_ini in /etc/php/*/apache2/php.ini; do
        if [[ -f "$php_ini" ]]; then
            # Enable error reporting
            sed -i 's/display_errors = Off/display_errors = On/' "$php_ini"
            sed -i 's/display_startup_errors = Off/display_startup_errors = On/' "$php_ini"
            sed -i 's/error_reporting = .*/error_reporting = E_ALL/' "$php_ini"
            
            # Allow file uploads
            sed -i 's/file_uploads = Off/file_uploads = On/' "$php_ini"
            sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 100M/' "$php_ini"
            sed -i 's/post_max_size = 8M/post_max_size = 100M/' "$php_ini"
        fi
    done
    
    # Enable Apache modules
    a2enmod rewrite
    a2enmod headers
    
    log_success "PHP configured for testing"
    create_checkpoint "php_config"
}

# Create comprehensive landing page
create_landing_page() {
    if check_checkpoint "landing_page"; then
        log_info "Landing page already created, skipping..."
        return
    fi
    
    log_step "Creating comprehensive landing page..."
    
    cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Application Security Testing Labs</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; color: white; margin-bottom: 40px; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .header p { font-size: 1.2em; opacity: 0.9; }
        .labs-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 40px; }
        .lab-card { background: white; border-radius: 10px; padding: 25px; box-shadow: 0 8px 25px rgba(0,0,0,0.1); transition: transform 0.3s ease; }
        .lab-card:hover { transform: translateY(-5px); }
        .lab-title { color: #333; font-size: 1.3em; margin-bottom: 15px; display: flex; align-items: center; }
        .lab-title .emoji { margin-right: 10px; font-size: 1.5em; }
        .lab-description { color: #666; margin-bottom: 15px; line-height: 1.5; }
        .lab-url { background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace; word-break: break-all; margin-bottom: 15px; }
        .lab-status { padding: 5px 15px; border-radius: 20px; font-size: 0.9em; font-weight: bold; }
        .status-running { background: #d4edda; color: #155724; }
        .status-ready { background: #cce5ff; color: #004085; }
        .info-section { background: white; border-radius: 10px; padding: 30px; margin-bottom: 20px; }
        .credentials { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; }
        .commands { background: #f8f9fa; border-radius: 5px; padding: 15px; font-family: monospace; white-space: pre-line; }
        .footer { text-align: center; color: white; margin-top: 40px; opacity: 0.8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Web Application Security Testing Labs</h1>
            <p>Complete Vulnerable Application Testing Environment - Ready for Penetration Testing Practice</p>
        </div>
        
        <div class="labs-grid">
            <div class="lab-card">
                <div class="lab-title"><span class="emoji">🌐</span>DVWA - Complete Testing Suite</div>
                <div class="lab-description">Damn Vulnerable Web Application with SQL Injection, XSS, CSRF, Session Management, and more</div>
                <div class="lab-url">http://localhost/dvwa/</div>
                <div class="credentials">Credentials: admin / password</div>
                <div class="lab-status status-running">RUNNING</div>
            </div>
            
            <div class="lab-card">
                <div class="lab-title"><span class="emoji">🧃</span>OWASP Juice Shop</div>
                <div class="lab-description">Modern web application with OWASP Top 10 vulnerabilities including NoSQL injection and IDOR</div>
                <div class="lab-url">http://localhost:3000/</div>
                <div class="lab-status status-running">RUNNING</div>
            </div>
            
            <div class="lab-card">
                <div class="lab-title"><span class="emoji">🏦</span>CSRF Banking Lab</div>
                <div class="lab-description">Vulnerable banking application for Cross-Site Request Forgery (CSRF) attack testing</div>
                <div class="lab-url">http://localhost/csrf_lab/login.php</div>
                <div class="credentials">Test with: alice / password123</div>
                <div class="lab-status status-running">RUNNING</div>
            </div>
            
            <div class="lab-card">
                <div class="lab-title"><span class="emoji">🔓</span>IDOR API Endpoints</div>
                <div class="lab-description">Insecure Direct Object Reference testing with vulnerable user API</div>
                <div class="lab-url">http://localhost/api/user.php?id=101</div>
                <div class="lab-description">Test with IDs: 101, 102, 103, 104, 105</div>
                <div class="lab-status status-running">RUNNING</div>
            </div>
            
            <div class="lab-card">
                <div class="lab-title"><span class="emoji">💻</span>CGI Command Injection</div>
                <div class="lab-description">Classic CGI script vulnerable to command injection attacks</div>
                <div class="lab-url">http://localhost/cgi-bin/hello.cgi?name=test</div>
                <div class="lab-description">Try: ?name=test; cat /etc/passwd</div>
                <div class="lab-status status-running">RUNNING</div>
            </div>
            
            <div class="lab-card">
                <div class="lab-title"><span class="emoji">🎯</span>CSRF Attack Page</div>
                <div class="lab-description">Malicious page demonstrating CSRF attacks against banking application</div>
                <div class="lab-url">http://localhost/attacker/csrf_attack.html</div>
                <div class="lab-description">Use after logging into banking app</div>
                <div class="lab-status status-ready">READY</div>
            </div>
        </div>
        
        <div class="info-section">
            <h2>🛡️ Burp Suite Setup Instructions</h2>
            <h3>1. Basic Configuration</h3>
            <ol>
                <li>Open Burp Suite Community Edition</li>
                <li>Go to <strong>Proxy → Options</strong></li>
                <li>Ensure proxy listener is on <code>127.0.0.1:8080</code></li>
                <li>Configure browser proxy settings to <code>127.0.0.1:8080</code></li>
            </ol>
            
            <h3>2. SSL Certificate (for HTTPS)</h3>
            <ol>
                <li>Visit <code>http://burp</code> in configured browser</li>
                <li>Download CA Certificate</li>
                <li>Install in browser certificate store</li>
            </ol>
            
            <div class="credentials">
                <strong>🔐 Database Information:</strong><br>
                • MySQL Root Password: root123<br>
                • DVWA Database: dvwa<br>
                • API Database: apitest<br>
                • CSRF Database: csrf_lab
            </div>
        </div>
        
        <div class="info-section">
            <h2>🔧 System Management Commands</h2>
            <div class="commands">
# Check services status
sudo systemctl status apache2 mariadb juice-shop

# View logs
sudo tail -f /var/log/apache2/error.log
sudo journalctl -f -u juice-shop

# Restart services
sudo systemctl restart apache2 mariadb

# Reset DVWA database
Visit: http://localhost/dvwa/setup.php
            </div>
        </div>
        
        <div class="footer">
            <p>🔍 Happy Ethical Hacking! Remember to only test on authorized systems.</p>
            <p>Version 4.0 - Complete Atomic Security Lab Environment</p>
        </div>
    </div>
</body>
</html>
EOF
    
    chown www-data:www-data /var/www/html/index.html
    
    log_success "Landing page created"
    create_checkpoint "landing_page"
}

# Service validation
validate_services() {
    log_step "Validating all services..."
    
    local services=("apache2" "mariadb")
    local all_running=true
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log_success "✓ $service is running"
        else
            log_error "✗ $service is not running"
            systemctl start "$service" || true
            all_running=false
        fi
    done
    
    # Check Juice Shop
    if systemctl is-active --quiet juice-shop; then
        log_success "✓ Juice Shop is running"
    else
        log_error "✗ Juice Shop is not running"
        systemctl start juice-shop || true
        all_running=false
    fi
    
    # Check web server accessibility
    if curl -s -o /dev/null -w "%{http_code}" http://localhost | grep -q "200"; then
        log_success "✓ Web server is accessible"
    else
        log_warn "✗ Web server may not be fully accessible"
        all_running=false
    fi
    
    if $all_running; then
        log_success "All services validated successfully"
    else
        log_warn "Some services may need manual attention"
    fi
}

# Cleanup function
cleanup_on_error() {
    log_error "Script interrupted. Cleaning up..."
    # Add any cleanup operations here if needed
    exit 1
}

# Final completion message
show_completion_message() {
    echo ""
    echo -e "${GREEN}################################################################${NC}"
    echo -e "${GREEN}#                 🎉 SETUP COMPLETE! 🎉                      #${NC}"
    echo -e "${GREEN}################################################################${NC}"
    echo ""
    echo "🚀 All vulnerable web application labs are ready for testing!"
    echo ""
    echo "📍 Quick Access Links:"
    echo "   • Main Dashboard: http://localhost/"
    echo "   • DVWA: http://localhost/dvwa/ (admin/password)"
    echo "   • Juice Shop: http://localhost:3000/"
    echo "   • CSRF Lab: http://localhost/csrf_lab/login.php (alice/password123)"
    echo "   • API Testing: http://localhost/api/user.php?id=101"
    echo "   • CGI Injection: http://localhost/cgi-bin/hello.cgi?name=test"
    echo ""
    echo "🔧 Lab Coverage:"
    echo "   ✅ HTTP Request/Response Analysis"
    echo "   ✅ SQL Injection (Multiple variants)"
    echo "   ✅ Cross-Site Scripting (XSS)"
    echo "   ✅ Cross-Site Request Forgery (CSRF)"
    echo "   ✅ Insecure Direct Object Reference (IDOR)"
    echo "   ✅ Session Management Testing"
    echo "   ✅ Command Injection"
    echo "   ✅ NoSQL Injection (Juice Shop)"
    echo "   ✅ Authentication Bypasses"
    echo "   ✅ Access Control Issues"
    echo ""
    echo "🛡️ Next Steps:"
    echo "   1. Configure Burp Suite proxy (127.0.0.1:8080)"
    echo "   2. Set browser proxy settings"
    echo "   3. Visit http://localhost/ to start testing"
    echo "   4. Initialize DVWA database: http://localhost/dvwa/setup.php"
    echo "   5. Set DVWA security level to 'Low' for initial testing"
    echo ""
    echo "🔐 Important Information:"
    echo "   • MySQL root password: root123"
    echo "   • Setup log: /tmp/lab_setup_checkpoints.log"
    echo "   • All services configured for automatic startup"
    echo ""
    echo "⚠️  Remember: Only test on authorized systems!"
    echo "🔍 Happy Ethical Hacking!"
    echo ""
}

# Main execution function
main() {
    # Setup error handling
    trap cleanup_on_error INT TERM ERR
    
    print_banner
    
    # Initialize checkpoint log
    echo "$(date): Lab setup started" > /tmp/lab_setup_checkpoints.log
    
    # Execute setup steps
    check_root
    detect_os
    update_system
    install_lamp_stack
    configure_mysql
    install_nodejs
    setup_dvwa
    setup_juice_shop
    create_api_endpoints
    setup_csrf_lab
    setup_cgi_lab
    configure_php
    create_landing_page
    
    # Restart services to ensure everything is working
    log_step "Restarting all services..."
    systemctl restart apache2 mariadb || true
    systemctl restart juice-shop || true
    sleep 5
    
    # Final validation
    validate_services
    
    # Completion
    create_checkpoint "complete_setup"
    show_completion_message
}

# Execute main function with all arguments
main "$@"

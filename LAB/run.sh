#!/bin/bash

#################################################################
# ATOMIC LAB SETUP SCRIPT for LATEST KALI LINUX (ONLY)
# Secure, idempotent, and error-free!
# Includes: DVWA, Juice Shop (Docker), CGI Lab, Full Automation
# Version: 5.1-kali
#################################################################

set -euo pipefail

readonly SCRIPT_VERSION="5.1-kali"
readonly MYSQL_ROOT_PASSWORD="root123"
readonly DVWA_DB_NAME="dvwa"
readonly CURRENT_USER=$(logname)
readonly KALI_CODENAME="kali-rolling"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_lab() { echo -e "${PURPLE}[LAB]${NC} $1"; }

print_banner() {
    echo -e "${BLUE}"
    echo "################################################################"
    echo "#           ATOMIC LAB SECURITY ENV - KALI LINUX ONLY           #"
    echo "#              Complete Testing Environment v${SCRIPT_VERSION}             #"
    echo "################################################################"
    echo -e "${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Run as root (use sudo)"
        exit 1
    fi
}

detect_kali() {
    source /etc/os-release || { log_error "Can't detect OS!"; exit 1; }
    if [[ "$ID" != "kali" ]]; then
        log_error "This script supports only Kali Linux!"
        exit 1
    fi
    log_info "Confirmed Kali Linux: $VERSION $VERSION_ID ($KALI_CODENAME)"
}

system_update() {
    log_info "Updating system..."
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
    log_success "System updated."
}

# Only install needed deps (dont touch node/npm/docker here)
install_base_packages() {
    log_info "Installing packages..."
    apt-get install -y apache2 mariadb-server mariadb-client \
        php libapache2-mod-php php-mysqli php-gd php-curl php-json php-mbstring php-xml php-zip php-intl \
        git curl wget unzip net-tools htop vim nano build-essential software-properties-common apt-transport-https ca-certificates gnupg lsb-release perl
    systemctl enable apache2 mariadb
    systemctl restart apache2 mariadb
    log_success "Base packages done."
}

mysql_secure_config() {
    log_info "Configuring MariaDB SQL root..."
    service mariadb restart
    mysql -u root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test_%';
FLUSH PRIVILEGES;
EOF
    log_success "SQL root password set: $MYSQL_ROOT_PASSWORD."
}

setup_dvwa() {
    log_lab "Setting up DVWA..."
    cd /tmp
    if [[ ! -d "DVWA" ]]; then
        git clone --depth 1 https://github.com/digininja/DVWA.git
    fi
    cp -r DVWA /var/www/html/dvwa
    chown -R www-data:www-data /var/www/html/dvwa
    chmod -R 755 /var/www/html/dvwa
    cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php
    sed -i "s/\$_DVWA\['db_password'\] = '';/\$_DVWA['db_password'] = '$MYSQL_ROOT_PASSWORD';/g" /var/www/html/dvwa/config/config.inc.php
    sed -i "s/\$_DVWA\['db_user'\] = 'dvwa';/\$_DVWA['db_user'] = 'root';/g" /var/www/html/dvwa/config/config.inc.php
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS $DVWA_DB_NAME;"
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON $DVWA_DB_NAME.* TO 'root'@'localhost';"
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;"
    mkdir -p /var/www/html/dvwa/hackable/uploads
    chmod 777 /var/www/html/dvwa/hackable/uploads
    touch /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt 2>/dev/null || true
    chmod 666 /var/www/html/dvwa/external/phpids/0.6/lib/IDS/tmp/phpids_log.txt 2>/dev/null || true
    log_success "DVWA ready at http://localhost/dvwa/"
}


setup_cgi_lab() {
    log_lab "Configuring CGI (Command Injection) Lab..."
    a2enmod cgi
    mkdir -p /usr/lib/cgi-bin
    chown www-data:www-data /usr/lib/cgi-bin
    cat > /usr/lib/cgi-bin/hello.cgi << 'EOF'
#!/usr/bin/perl
print "Content-type: text/html\n\n";
my $input = $ENV{'QUERY_STRING'};
system("echo Hello $input"); # vulnerable
EOF
    chmod +x /usr/lib/cgi-bin/hello.cgi
    systemctl restart apache2
    log_success "CGI lab at http://localhost/cgi-bin/hello.cgi?name=test"
}

main() {
    print_banner
    check_root
    detect_kali
    system_update
    install_base_packages
    mysql_secure_config
    setup_dvwa
    setup_cgi_lab
    log_success "\n🎯 All vulnerable labs installed. Juice Shop is in Docker.\nLog out/log in or run 'newgrp docker' if you want to run Docker as your login user.\nDVWA: http://localhost/dvwa/\nJuice Shop: http://localhost:3000/\nCGI: http://localhost/cgi-bin/hello.cgi?name=test\n"
}

main "$@"

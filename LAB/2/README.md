### 1. Download and Run
```bash
# Download the script
wget https://raw.githubusercontent.com/your-repo/complete-vuln-labs-setup.sh

# Make it executable
chmod +x complete-vuln-labs-setup.sh

# Run as root
sudo ./complete-vuln-labs-setup.sh
```

### 2. What This Script Sets Up

**Lab 1: HTTP Basics & Stack Setup**
- Complete LAMP stack (Apache, MariaDB, PHP)
- DVWA installation and configuration
- Landing page with all lab links

**Lab 2: SQL Injection**
- DVWA SQL injection modules
- Custom vulnerable PHP script (`/sql_test.php`)
- Pre-configured database with test data

**Lab 3: NoSQL Injection**
- OWASP Juice Shop with MongoDB backend
- Systemd service for automatic startup
- REST API endpoints for testing

**Lab 4: IDOR/Access Control**
- Juice Shop user profile endpoints
- API routes for testing broken access control

**Lab 5: Cross-Site Scripting (XSS)**
- DVWA reflected XSS module
- Pre-configured vulnerable input fields

**Lab 6: Session Management**
- DVWA login system with session cookies
- Session fixation vulnerabilities enabled

**Bonus: Command Injection**
- CGI-enabled Apache with vulnerable Perl script
- Direct command execution testing

### 3. Post-Installation Access

After running the script, access your labs at:

- **Main Dashboard:** `http://localhost/`
- **DVWA:** `http://localhost/dvwa/` (admin/password)
- **Juice Shop:** `http://localhost:3000/`
- **CGI Lab:** `http://localhost/cgi-bin/hello.cgi?name=test`

### 4. Quick Setup Commands

```bash
# One-liner installation
curl -sSL https://raw.githubusercontent.com/your-repo/complete-vuln-labs-setup.sh | sudo bash

# Or manual download and run
sudo bash complete-vuln-labs-setup.sh
```

### 5. What's Included

✅ **Automated LAMP Stack Setup**  
✅ **DVWA with Database Configuration**  
✅ **OWASP Juice Shop via npm**  
✅ **CGI Command Injection Lab**  
✅ **Session Management Testing**  
✅ **SQL/NoSQL/XSS/IDOR Labs**  
✅ **Service Management & Monitoring**  
✅ **Landing Page with Lab Links**

This script automates everything from system updates to service configuration, making all 6 labs ready for immediate penetration testing with Burp Suite!

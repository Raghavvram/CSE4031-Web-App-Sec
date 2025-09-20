### 1. Download and Execute
```bash
# Make the script executable
chmod +x web-app-testing-labs.sh

# Run as root (required for system installation)
sudo ./web-app-testing-labs.sh
```

### 2. What This Script Sets Up

**Complete Testing Environment:**
- **LAMP Stack** (Apache, MySQL, PHP)
- **DVWA** (Damn Vulnerable Web Application)
- **Custom Testing Endpoints** for each lab
- **API Endpoints** for IDOR testing
- **Session Management** test pages
- **Comprehensive Dashboard** with all lab links

### 3. Lab Coverage

**Lab 1: HTTP Request Interception**
- Login forms for HTTP traffic capture
- Multiple form types (login, contact)
- POST/GET request examples

**Lab 2: SQL Injection Testing**
- DVWA SQLi modules
- Test endpoints with various SQL payloads
- Database manipulation examples

**Lab 3: Cross-Site Scripting (XSS)**
- Reflected XSS testing pages
- Stored XSS demonstration
- Vulnerable vs. secure implementations

**Lab 4: Broken Access Control (IDOR)**
- User API endpoints (/api/user.php?id=101-105)
- Multiple user profiles for testing
- Authorization bypass examples

**Lab 5: Session Management Testing**
- Session cookie capture and reuse
- PHPSESSID manipulation
- Session hijacking demonstrations

### 4. Key Features

✅ **Complete DVWA Integration**  
✅ **Custom Vulnerable Endpoints**  
✅ **API Testing Environment**  
✅ **Session Management Labs**  
✅ **Interactive Testing Dashboard**  
✅ **Comprehensive Documentation**  
✅ **Burp Suite Integration Guide**  
✅ **Sample Payloads Included**

### 5. After Installation

**Access Points:**
- **Main Dashboard:** `http://localhost/`
- **Lab 1 (HTTP):** `http://localhost/lab1_http_test.html`
- **Lab 2 (SQLi):** `http://localhost/dvwa/vulnerabilities/sqli/`
- **Lab 3 (XSS):** `http://localhost/lab3_xss_test.html`
- **Lab 4 (IDOR):** `http://localhost/api/user.php?id=101`
- **Lab 5 (Session):** `http://localhost/lab5_session_test.html`

**Testing Guide:** `/home/[username]/WEB_TESTING_GUIDE.md`

### 6. Burp Suite Testing Workflow

1. **Configure Browser Proxy:** 127.0.0.1:8080
2. **Enable Burp Intercept:** Proxy → Intercept is on
3. **Visit Lab URLs:** Submit forms and capture requests
4. **Use Repeater:** Modify parameters and test payloads
5. **Analyze Responses:** Look for vulnerabilities

### 7. Sample Test Payloads

**SQL Injection:**
- `1' OR '1'='1`
- `1' UNION SELECT 1,user()--`

**XSS:**
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert(1)>`

**IDOR:**
- Change `id=101` to `id=102` in API calls

This script provides a complete, production-ready web application security testing environment with all 5 labs fully configured and ready for immediate penetration testing practice with Burp Suite!

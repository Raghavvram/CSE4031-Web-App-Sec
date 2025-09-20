### 1. Download and Execute
```bash
# Make the script executable
chmod +x web-authoring-tools-lab.sh

# Run as root
sudo ./web-authoring-tools-lab.sh
```

### 2. What This Script Sets Up

**Complete LAMP Stack:**
- Apache web server with PHP support
- MariaDB/MySQL database
- PHP with security extensions
- VS Code installation

**Web Authoring Tool Examples:**

1. **Adobe Dreamweaver Style Forms** - Basic HTML with vulnerable PHP handlers
2. **Microsoft FrontPage Style** - Legacy forms with classic vulnerabilities  
3. **VS Code Generated Forms** - Modern-looking but still vulnerable code
4. **WordPress CMS** - Includes built-in security features for comparison

**Vulnerable Components:**
- Login forms susceptible to XSS and SQL injection
- Contact forms with input validation issues
- Registration forms with output encoding problems
- Database handlers without prepared statements

### 3. Testing with Burp Suite

After setup, you can:

1. **Configure Burp Suite** proxy on port 8080
2. **Visit vulnerable forms** at:
   - `http://localhost/dreamweaver_login.html`
   - `http://localhost/frontpage_contact.html` 
   - `http://localhost/vscode_form.html`
3. **Capture requests** in Burp Proxy
4. **Test payloads** using Burp Repeater:
   - **XSS:** `<script>alert('XSS')</script>`
   - **SQL Injection:** `' OR '1'='1`

### 4. Key Features

✅ **Multiple Authoring Tool Simulations**  
✅ **Vulnerable and Secure Code Examples**  
✅ **WordPress CMS with Built-in Security**  
✅ **VS Code Installation for Modern Development**  
✅ **Complete Database Setup with Test Data**  
✅ **Landing Page with Testing Instructions**  
✅ **Burp Suite Integration Guide**

### 5. Lab Coverage

- **Step 1:** Different authoring tool outputs (HTML forms)
- **Step 2:** Burp Suite traffic capture and analysis  
- **Step 3:** Vulnerability testing (XSS, SQLi)
- **Step 4:** Tool comparison and security assessment

This script provides a comprehensive environment for studying how different web authoring tools can generate vulnerable code and how to identify these vulnerabilities using professional security testing tools like Burp Suite.


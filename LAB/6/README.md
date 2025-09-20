### 1. Download and Execute
```bash
# Make the script executable
chmod +x csrf-attack-lab.sh

# Run as root (required for system installation)
sudo ./csrf-attack-lab.sh
```

### 2. What This Script Sets Up

**Complete CSRF Testing Environment:**
- **DVWA** with CSRF vulnerability module
- **Custom Banking Application** (vulnerable to CSRF)
- **Multiple Attack Pages** demonstrating different CSRF techniques
- **Secure Implementation Examples** showing proper CSRF protection
- **Comprehensive Dashboard** with all lab components

### 3. CSRF Attack Techniques Covered

**Attack Methods:**
- **Social Engineering CSRF:** Fake prize/bonus claims
- **Auto-Submit CSRF:** Automatic form submission attacks
- **Hidden Iframe CSRF:** Invisible attack execution
- **Image-Based CSRF:** Using img tags for GET-based attacks
- **JSON-Based CSRF:** Modern API attack techniques

**Vulnerable Applications:**
- **DVWA Password Change:** Classic CSRF demonstration
- **Banking Transfers:** Money transfer via CSRF
- **Email Changes:** Account hijacking preparation
- **Multi-Step Attacks:** Chained CSRF requests

### 4. Key Features

✅ **Complete DVWA Integration**  
✅ **Custom Vulnerable Banking App**  
✅ **Multiple Attack Vector Demonstrations**  
✅ **Social Engineering Examples**  
✅ **CSRF Prevention Implementation**  
✅ **Burp Suite Integration**  
✅ **Comprehensive Testing Guide**  
✅ **Real-World Attack Scenarios**

### 5. Testing Workflow

**Step 1: Access Vulnerable Apps**
- **DVWA:** `http://localhost/dvwa/` (admin/password)
- **Banking:** `http://localhost/csrf_lab/login.php` (alice/password123)

**Step 2: Capture Legitimate Requests**
- Use Burp Suite to intercept form submissions
- Note the request structure and parameters

**Step 3: Execute CSRF Attacks**
- Visit attack pages: `http://localhost/attacker/`
- Click malicious buttons while logged into target apps
- Observe unauthorized actions performed

**Step 4: Study Prevention**
- Visit: `http://localhost/secure/csrf_secure_example.php`
- See proper CSRF token implementation

### 6. Attack Pages Included

**Prize-Based Attack:** `/attacker/csrf_password_attack.html`
- Social engineering with fake iPhone giveaway
- Hidden CSRF form targeting password change

**Auto-Submit Attack:** `/attacker/csrf_auto_attack.html`
- Automatic form submission after loading
- Simulates drive-by attack scenario

**Banking Attack:** `/attacker/csrf_bank_attack.html`
- Targets money transfer functionality
- Combined with email change attack

**Image-Based Attack:** `/attacker/csrf_image_attack.html`
- Hidden iframe executing CSRF
- Disguised as innocent content

### 7. Learning Outcomes

**Attack Understanding:**
- How CSRF attacks leverage browser trust
- Different attack vector implementations
- Social engineering techniques
- Request structure analysis

**Defense Knowledge:**
- CSRF token implementation
- SameSite cookie configuration
- Referer header validation
- Double-submit cookie patterns

### 8. Documentation Included

**Complete Guide:** `/home/[username]/CSRF_ATTACK_GUIDE.md`
- Detailed testing procedures
- Attack technique explanations
- Prevention method implementations
- Real-world examples and scenarios

This script provides a complete, hands-on CSRF attack laboratory with multiple vulnerable applications, various attack techniques, and comprehensive educational materials for understanding both exploitation and prevention of CSRF vulnerabilities!

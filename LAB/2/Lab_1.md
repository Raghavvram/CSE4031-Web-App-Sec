Here is the structured summary for Lab 1 – HTTP Basics & Setting Up Stacks:

***

### Lab 1 – HTTP Basics & Setting Up Stacks

#### Objective
Understand the fundamental structure of HTTP requests and responses and deploy a vulnerable web application (DVWA) on a local server stack to capture and analyze HTTP traffic.

#### Procedure
1. **Set up web server and DB:**
   - For Windows: Install **XAMPP** (includes Apache, PHP, MySQL).
   - For Linux: Install **LAMP stack** (Apache, PHP, MySQL).
2. **Deploy DVWA:**
   - Download the Damn Vulnerable Web App (DVWA).
   - Copy the DVWA folder to your web root:
     - For XAMPP: `C:\xampp\htdocs\dvwa\`
     - For LAMP: `/var/www/html/dvwa/`
3. **Configure database:**
   - Edit `config/config.inc.php` in the DVWA directory to set DB credentials.
4. **Start services:**
   - Start Apache and MySQL via XAMPP control panel or system commands (`sudo systemctl start apache2 mysql`).
5. **Capture HTTP traffic:**
   - Launch Burp Suite.
   - Set your browser to use Burp as a proxy.
   - Browse to `http://localhost/dvwa/login.php`.
   - Burp Proxy will intercept the GET request.

#### Code/Request & Output Example

**Captured HTTP Request:**
```
GET /dvwa/login.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
Accept: text/html,application/xhtml+xml,...
```

**HTTP Response from Server:**
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 1540
...
```

- Observing these messages in Burp Suite unveils the structure of the HTTP interaction — headers, methods, status codes, and content types.
- This foundation aids in understanding later vulnerability testing in web apps.

***

This lab facilitates familiarity with HTTP mechanics and local vulnerable app deployment to prepare for hands-on security testing with tools like Burp Suite.

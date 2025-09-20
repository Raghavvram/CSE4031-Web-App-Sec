### Lab 2 – Databases & SQL Injection

#### Objective
Demonstrate SQL Injection vulnerability by exploiting a PHP script connected to a MySQL database that unsafely embeds user input directly into a SQL query.

#### Procedure
1. **Vulnerable PHP code snippet (as in DVWA low security):**
   ```php
   $id = $_GET['id'];
   $result = mysqli_query($conn, "SELECT * FROM users WHERE id='$id'");
   ```
   Here, user-supplied input `$id` is directly inserted into the query without any sanitization or prepared statements.

2. **Test steps in Burp Suite:**
   - Open Burp Suite and configure your browser to use Burp as a proxy.
   - Visit the vulnerable URL:  
     `http://localhost/dvwa/vulnerabilities/sqli/?id=1`
   - In Burp Suite Proxy with intercept enabled, capture the HTTP GET request.
   - Right-click the captured request → Send to Repeater tab.
   - In Repeater, modify the `id` parameter with this SQL injection payload:  
     ```
     id=1' OR '1'='1
     ```
   - Send the modified request.

#### Code Result/Output
- Instead of returning only the user with ID 1, the database returns **all user records** because the injected SQL condition `' OR '1'='1` always evaluates to true.
- Example response in the web page might show:
  ```
  User ID: 1, Username: admin
  User ID: 2, Username: guest
  User ID: 3, Username: johndoe
  ```
- This confirms the presence of a SQL injection vulnerability.

***

This exercise highlights the risks of dynamic SQL queries with unsanitized input and the necessity of using prepared statements or parameterized queries to mitigate SQL injection.


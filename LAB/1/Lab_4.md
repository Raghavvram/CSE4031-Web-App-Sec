## 1. Setup DVWA
- Install or run DVWA locally, e.g., via Docker or manual setup.
- Login to DVWA (`admin`/`password`).
- Set security level to Low (to allow XSS vulnerabilities).
- Navigate to the Reflected XSS page:
  ```
  http://localhost/dvwa/vulnerabilities/xss_r/
  ```

## 2. Initial Request
- In your browser, enter a test query parameter to generate a request, such as:
  ```
  GET /dvwa/vulnerabilities/xss_r/?q=test
  ```

## 3. Capture and Modify Request in Burp Suite
- Ensure your browser is configured to proxy through Burp Suite.
- In Burp Suite Proxy, have intercept turned on.
- Visit the above URL to capture the GET request in Burp.
- Right-click the intercepted request → Send to Repeater.

## 4. Inject XSS Payload
- In Burp Repeater, modify the query string parameter `q` with this payload:
  ```
  <script>alert('XSS')</script>
  ```
  So the full GET request looks like:
  ```
  GET /dvwa/vulnerabilities/xss_r/?q=<script>alert('XSS')</script>
  ```
- Send the request from Burp Repeater.

## 5. Observe Reflected XSS
- In the response panel, check if the payload appears reflected in the HTML.
- Open the response in your browser using "Show response in browser" in Burp.
- If an alert box with 'XSS' pops up, the reflected XSS is confirmed.

***

### Summary

| Step                | Action                                      | Expected Outcome                     |
|---------------------|---------------------------------------------|------------------------------------|
| Setup DVWA          | Navigate to reflected XSS page              | Page loads with input field        |
| Capture request      | Intercept GET with `q=test`                  | Request shown in Burp              |
| Modify input         | Set `q=<script>alert('XSS')</script>`       | Payload sent in URL                |
| Send request         | Send via Repeater                            | Response includes reflected script |
| Confirm XSS          | View response in browser, see alert popup   | JavaScript executes, alert pops up |

This proves the web app reflects unsafe input directly into the response causing Reflected Cross-Site Scripting vulnerability.


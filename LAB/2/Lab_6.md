### Lab 6 – Session Management Vulnerabilities (Session Fixation)

#### Objective
Test session fixation vulnerability by capturing and reusing session cookies to impersonate a logged-in user, verifying that the application does not properly manage session identifiers.

#### Procedure
1. **Setup:**
   - Use DVWA with login functionality enabled.
2. **Capture login request:**
   - Configure your browser to use Burp Suite as proxy.
   - Log in to DVWA normally.
   - In Burp Proxy, intercept the login request.
3. **Note the session cookie:**
   - Observe the `PHPSESSID` cookie set in the response headers or request headers.
4. **Reuse the session cookie:**
   - Copy the `PHPSESSID` cookie value.
   - Open a different browser or incognito window.
   - Manually set the `PHPSESSID` cookie to the captured value (using browser dev tools or an extension).
5. **Access the DVWA app using the reused session cookie.**
6. **Check if access is granted without re-authentication.**

#### Code Result/Output
- If the second browser with the reused `PHPSESSID` can access logged-in pages without logging in:
  ```
  Access granted to DVWA logged-in area.
  ```
- This confirms a session fixation vulnerability allowing session hijacking by reusing fixed session identifiers.

***

This lab highlights the risks when session management does not regenerate or securely handle session IDs after login, enabling attackers to hijack sessions.

Would you like detailed mitigation steps or automation scripts for session testing?

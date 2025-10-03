# Attacks on Session and Access Control

## 1\. The Need for State

### Explanation

The HTTP protocol is fundamentally stateless, meaning each request is treated as an independent transaction. To create interactive experiences like user logins or shopping carts, web applications must implement a mechanism to remember and identify a user across multiple requests. This is called maintaining "state," and it is typically achieved by issuing a unique session token to each user. Attacks against sessions work by exploiting this state mechanism to impersonate legitimate users.

### Code/Example

The most common method for transmitting session tokens is through HTTP cookies.

  * The server first issues a token to a new client using the `Set-Cookie` response header.
    ```http
    Set-Cookie: ASP.NET_SessionId=mza2j1454804cwbgwb2ttj55
    ```
  * The browser then automatically includes this cookie in all subsequent requests to that server.
    ```http
    Cookie: ASP.NET_SessionId=mza2ji454804cwbgwb2ttj55
    ```

### Output

The application uses the submitted token to retrieve the user's session data, allowing them to remain authenticated and access protected resources without having to re-enter credentials for every page view.

### Diagram

```ascii
+--------+                                  +--------+
|        |  1. Request (no token)           |        |
| Client | -------------------------------> | Server |
|        |                                  |        |
|        |  2. Response (Set-Cookie: token) |        |
|        | <------------------------------- |        |
+--------+                                  +--------+
     |
     | 3. Subsequent Requests (Cookie: token)
     |
+--------+                                  +--------+
|        | -------------------------------> | Server |
| Client |                                  |        |
|        | <------------------------------- |        |
|        |  4. Response (user is recognized)|        |
+--------+                                  +--------+
```

-----

## 2\. Weakness in Token Generation & Handling

### Explanation

The security of a session mechanism depends on its tokens being unique, unpredictable, and properly managed. If tokens are generated using weak or predictable methods, an attacker can guess or extrapolate the tokens issued to other users and hijack their sessions.

### Code/Example: Meaningful Tokens

Some applications create tokens by encoding user-specific information, which can be reverse-engineered.

  * **Token Value:**
    ```
    75736572306461663b6170703061646d696e3b646174653430312313223131
    ```
  * This token appears random but contains only hexadecimal characters.

### Output

By decoding the hex string, its meaningful structure is exposed. An attacker can forge tokens for other users (e.g., changing `daf` to `admin`) to escalate privileges.

  * **Decoded Value:**
    ```
    user=daf;app=admin;date=10/09/11 [cite: 357]
    ```

### Diagram

```ascii
+----------+   1. Captures own token:   +-------------------------------------+
| Attacker | ------------------------> | HexEncode("user=attacker;...")     |
+----------+                           +-------------------------------------+
     |
     | 2. Decodes token and finds the structure.
     | 3. Forges a new token for the 'admin' user.
     |
     +--> Submits new token: HexEncode("user=admin;...") --> [SESSION HIJACKED]
```

-----

## 3\. Hijacking Liberal Cookie Scope

### Explanation

Applications can specify a cookie's scope with the `domain` attribute. If this scope is set too liberally (e.g., to a parent domain like `.example.com` instead of `app.example.com`), the cookie will be sent to all subdomains. If a less secure application exists on another subdomain, it can be used as a vector to steal the sensitive session cookie.

### Code/Example

A secure application at `sensitiveapp.wahh-organization.com` sets a cookie with a liberal domain scope.

```http
Set-cookie: sessionid=12df098ad809a5219; domain=wahh-organization.com
```

This causes the cookie to be sent to all other subdomains, including a less secure one like `testapp.wahh-organization.com`.

### Output

An attacker can exploit a flaw like Cross-Site Scripting (XSS) on the less-secure `testapp` subdomain to run a script that captures the `sessionid` cookie. The attacker then uses this stolen cookie to hijack the user's session on the high-security `sensitiveapp`.

### Diagram

```ascii
    +----------------------------------+
    |       wahh-organization.com      |
    |                                  |
    |  +---------------------------+   |   +--------------------------+
    |  | sensitiveapp (Secure)     |   |   | testapp (Insecure)       |
    |  |                           |   |   |                          |
    |  | Sets cookie for parent -> | --|-> | <- Attacker steals cookie|
    |  +---------------------------+   |   +--------------------------+
    |                                  |
    +----------------------------------+
```

-----

## 4\. Securing Session Management (Best Practices)

### Explanation

[cite\_start]Secure session management requires both generating strong tokens and protecting them throughout their lifecycle[cite: 67, 1369]. Key practices include:

  * [cite\_start]**Generate Strong Tokens**: Tokens must be long, unique, and unpredictable, using cryptographically secure random functions[cite: 73, 74, 1374]. [cite\_start]All session state should be stored on the server, not in the token[cite: 1379].
  * [cite\_start]**Protect Tokens**: Transmit tokens only over HTTPS and use the `Secure` flag on cookies[cite: 68, 78, 1404, 1405]. [cite\_start]Never include tokens in URLs[cite: 79, 1410].
  * [cite\_start]**Lifecycle Management**: Invalidate sessions on the server after logout and periods of inactivity[cite: 69, 71, 81, 1413, 1414]. [cite\_start]Always generate a new session token after a user authenticates to prevent session fixation[cite: 69, 1441].
  * [cite\_start]**Log, Monitor, and Alert**: Log all session-related events and monitor for anomalies like brute-force guessing attempts (many requests with invalid tokens)[cite: 87, 90, 91, 1475]. [cite\_start]Alert administrators to suspicious activity[cite: 95, 1479].

### Example: Log, Monitor, and Alert

[cite\_start]An attacker attempts to guess valid session IDs by sending thousands of requests with random tokens[cite: 1475]. [cite\_start]The application's monitoring system detects a massive spike in failed session validations from a single IP address[cite: 1477].

### Output

[cite\_start]The system triggers an alert to an administrator, who can then investigate the attack and block the source IP address, mitigating the threat before the attacker can successfully guess a valid token[cite: 95, 1479].

### Diagram

```ascii
+----------+ --[Sends 1000s of invalid tokens]--> +--------------+
| Attacker |                                     | App Server   |
+----------+                                     | with Logging |
                                                 +--------------+
                                                        |
                                                        V
                                                 +-----------------+
                                                 | Monitoring System |
                                                 | (Detects anomaly) |
                                                 +-----------------+
                                                        |
                                                        V
                                                 +-----------------+
                                                 | Alert to Admin  |
                                                 | --> IP BLOCKED  |
                                                 +-----------------+
```

-----

## 5\. Common Vulnerability: Session Fixation

### Explanation

[cite\_start]A session fixation attack occurs when an attacker can force a victim to use a session token known to the attacker[cite: 16, 84, 102]. [cite\_start]When the victim logs in, the application associates their authenticated session with the attacker's token[cite: 17, 104]. [cite\_start]This is possible if the application fails to generate a new, fresh session token upon successful login[cite: 118, 1288].

### Example

1.  [cite\_start]An attacker visits the application and is issued a session token (e.g., `sessionid=ATTACKER_TOKEN`)[cite: 1281].
2.  [cite\_start]The attacker tricks the victim into clicking a link that contains this token: `http://example.com/login?sessionid=ATTACKER_TOKEN`[cite: 1281].
3.  The victim's browser adopts the attacker's token. [cite\_start]The victim then logs in with their own credentials[cite: 1281].

### Output

[cite\_start]Because the application did not issue a new token, the attacker's token is now authenticated as the victim[cite: 104]. [cite\_start]The attacker can now use `sessionid=ATTACKER_TOKEN` to access the victim's account and perform unauthorized actions[cite: 1281].

### Diagram

```ascii
+----------+  1. Get Token  +--------+  2. Send Link with Token  +--------+
| Attacker | <----------- | Server | ------------------------> | Victim |
+----------+              +--------+                           +--------+
                                                                   |
+----------+                                                       | 3. Victim Logs In
| Attacker |  4. Hijacks Authenticated Session                      |
|          | <---------------------------------------------------- +
+----------+
```

-----

## 6\. Common Vulnerability: Improper Session Termination

### Explanation

[cite\_start]A secure logout function must invalidate the session on the server side[cite: 1413]. [cite\_start]A common vulnerability is when the "logout" button only performs a client-side action, such as clearing the session cookie from the browser[cite: 1247, 1250]. [cite\_start]The session token itself remains valid on the server[cite: 1248].

### Code/Example

[cite\_start]When a user clicks the logout button, the following client-side JavaScript executes, which simply blanks the cookie and redirects the user[cite: 1250]. No request is sent to the server to invalidate the session.

```javascript
[cite_start]document.cookie="sess="; [cite: 1541]
[cite_start]document.location="/" [cite: 1542]
```

### Output

[cite\_start]The user appears to be logged out, but their session is still active on the server[cite: 1248]. [cite\_start]An attacker who previously captured the session token can simply resubmit it and continue to access the user's account as if they never logged out[cite: 1251].

### Diagram

```ascii
+--------+   1. User clicks logout.     +------------------------+
| Victim | ------------------------> | Browser executes script|
+--------+   (Appears logged out)      | (Cookie is cleared)    |
                                     +------------------------+

+----------+  2. Attacker has old token. +--------+
| Attacker | -------------------------> | Server | --> Access Granted
+----------+                           +--------+ (Session is still valid)
```

-----

## 7\. Testing with Different User Accounts

### Explanation

[cite\_start]The most effective way to test access controls is to use multiple user accounts with different privilege levels (e.g., an administrator and a normal user)[cite: 134, 1747]. [cite\_start]By logging in as a high-privilege user, you can map out all sensitive functionality, and then attempt to access those same functions as a low-privilege user to test for flaws[cite: 1751]. [cite\_start]This can reveal both vertical (gaining higher rights) and horizontal (accessing another user's data) privilege escalation vulnerabilities[cite: 1751, 1752].

### Example

1.  [cite\_start]An administrator logs in and accesses the user management page at `/admin/ListUsers.ashx`[cite: 1789].
2.  [cite\_start]A normal user logs in and does not see a link to this page[cite: 1793].
3.  [cite\_start]The normal user then attempts to browse directly to the `/admin/ListUsers.ashx` URL[cite: 1792].

### Output

[cite\_start]If the access controls are broken, the server returns the exact same list of users to the normal user as it did to the administrator, confirming a critical vertical privilege escalation vulnerability[cite: 1793].

  * **Sample Output Table:**
    ```
    +-----+---------------+-----------+
    | Uid | Username      | User role |
    +-----+---------------+-----------+
    | 1   | admin         | admin     |
    | 24  | User          | User      |
    | 25  | Herman        | User      |
    +-----+---------------+-----------+
    ```

### Diagram

```ascii
+-------------+                                  +-------------------+
| Admin User  | --- browses to /admin/list ---> | Sees list of users|
+-------------+                                  +-------------------+

+-------------+                                  +-------------------+
| Normal User | --- browses to /admin/list ---> | Sees list of users| (VULNERABILITY)
+-------------+                                  +-------------------+
```

-----

## 8\. Testing Direct Access to Methods

### Explanation

[cite\_start]Applications often rely on client-side controls to hide or disable links to sensitive functions for low-privilege users[cite: 164]. [cite\_start]However, these UI restrictions are useless if the server does not enforce the same access control checks on the back end[cite: 164]. [cite\_start]An attacker can discover the URLs for these hidden functions by inspecting client-side code (like JavaScript) and then make direct requests to them, bypassing the UI entirely[cite: 161, 168].

### Code/Example

[cite\_start]An attacker, logged in as a normal user, inspects the application's JavaScript and finds code that only adds the "create user" menu item if the user is an admin[cite: 1607, 1612].

```javascript
[cite_start]var isAdmin = false; [cite: 1609]
[cite_start]if (isAdmin) [cite: 1610]
    [cite_start]adminMenu.addItem("/menus/secure/ff457/addNewPortalUser2.jsp", "create a new user"); [cite: 1611]
```

[cite\_start]The attacker now knows the hidden URL for the administrative function[cite: 1612].

### Output

[cite\_start]The attacker sends a direct request to `/menus/secure/ff457/addNewPortalUser2.jsp`[cite: 189]. [cite\_start]If the server is not performing proper authorization checks, it will serve the page, allowing the low-privilege user to perform the administrative action of creating a new user[cite: 196].

### Diagram

```ascii
+-------------+     1. UI hides link     +-------------------------+
| Normal User | -X--------------------> | /admin/createUser       |
+-------------+                         +-------------------------+
      |
      | 2. Attacker inspects JS, finds URL
      |
      | 3. Sends direct request to /admin/createUser
      V
+-------------+                         +-------------------------+
| Normal User | ----------------------> | Access granted! (FAIL)  |
+-------------+                         +-------------------------+
```

-----

## 9\. Testing Controls Over Static Resources

### Explanation

[cite\_start]Sometimes sensitive information is stored in static files (PDFs, backups, logs) that are located within the server's web root[cite: 198, 199, 201, 1673]. [cite\_start]When a user requests a static file, the web server often returns it directly without involving any application-level code[cite: 203, 1677]. [cite\_start]This means any access control logic defined within the application is completely bypassed[cite: 203, 1678].

### Example

[cite\_start]After making a payment, a user is given a link to download their purchased ebook[cite: 1674, 1675].

```
[cite_start]https://wahh-books.com/download/9780636628104.pdf [cite: 1676]
```

[cite\_start]The filename is a predictable identifier (an ISBN number)[cite: 1681].

### Output

[cite\_start]An attacker who has not paid for the book can simply guess or construct the URL and download the file directly[cite: 208, 1680]. [cite\_start]By iterating through known ISBNs, the attacker could potentially download the publisher's entire catalog for free[cite: 215, 1681].

### Diagram

```ascii
+----------+     1. Makes Payment      +----------------------+
| Good User| ------------------------> | Gets Link to PDF     |
+----------+                           +----------------------+

+----------+                           +----------------------+
| Attacker | ---X-- (skips payment)    |                      |
|          |                           |                      |
|          | --- 2. Guesses URL ---->  | Downloads PDF (FAIL) |
+----------+                           +----------------------+
```

-----

## 10\. Attacks on Encrypted Tokens: ECB Ciphers

### Explanation

[cite\_start]When an application encrypts meaningful data inside a token, it may use the Electronic Codebook (ECB) cipher mode[cite: 723]. [cite\_start]ECB is insecure because it encrypts each block of plaintext independently, meaning identical plaintext blocks produce identical ciphertext blocks[cite: 724, 726]. [cite\_start]This allows an attacker to copy, remove, or reorder the ciphertext blocks to manipulate the final decrypted message without needing the encryption key[cite: 758].

### Code/Example

[cite\_start]A token contains a user ID (`uid=218`)[cite: 733]. [cite\_start]An attacker registers a new username containing a target ID (`daf1`)[cite: 790].

  * The plaintext block for the original UID is `218;user`.
  * [cite\_start]The plaintext block containing the attacker's chosen ID is `1;time=6`[cite: 805].
  * [cite\_start]The attacker copies the ciphertext block corresponding to `1;time=6` and replaces the ciphertext block corresponding to `218;user`[cite: 813].

### Output

[cite\_start]When the server decrypts the manipulated token, the `uid` is now read as `1`[cite: 813]. [cite\_start]The application processes the request in the context of the user with ID 1, leading to a successful account takeover[cite: 836, 837].

### Diagram

```ascii
Original Ciphertext:
[ Block A ][ Block B ][ Block C ][ Block D ][ Block E: uid=218 ]

Attacker's Controlled Plaintext in another token:
[ ... ][ Block X: uid=1 ][ ... ]

Attacker's Manipulated Ciphertext:
[ Block A ][ Block B ][ Block C ][ Block D ][ Block X: uid=1 ]
     |
     V
Decrypted by Server --> User ID is now 1
```

-----

## 11\. Attacks on Encrypted Tokens: CBC Bit-Flipping

### Explanation

[cite\_start]Cipher Block Chaining (CBC) mode is more secure than ECB, as it XORs each plaintext block with the previous ciphertext block before encryption[cite: 843]. This dependency, however, can be exploited. [cite\_start]Modifying a single bit in a ciphertext block (`C[n-1]`) will completely corrupt the corresponding plaintext (`P[n-1]`), but it will cause a predictable, controlled, single-bit change in the *next* plaintext block (`P[n]`)[cite: 870]. This is a "bit-flipping" attack.

### Example

[cite\_start]An attacker wants to change their `uid` from 216 to 226[cite: 884]. They capture their encrypted token. [cite\_start]Using a tool like Burp Intruder's "bit flipper," they systematically modify each bit in the ciphertext block that comes *just before* the block containing the `uid` value[cite: 885].

### Output

[cite\_start]Most modified tokens will be rejected as invalid[cite: 882]. [cite\_start]However, a specific bit flip in the right position will cause the decrypted `uid` value to change from 216 to 226[cite: 884]. [cite\_start]The application's response will suddenly show that the attacker is logged in as a different user, confirming a successful session hijack[cite: 918].

### Diagram

```ascii
CBC Decryption Process:

Ciphertext[N-1]  --------------------------------------->|
                                                         |
Ciphertext[N] --> [DECRYPT with Key] --+--> [ XOR ] --> Plaintext[N]

Bit-Flipping Attack:

Attacker flips one bit in Ciphertext[N-1] ------------>|
                                                       |
Ciphertext[N] --> [DECRYPT with Key] --+--> [ XOR ] --> Plaintext[N] is now predictably altered.
                                                        (e.g., uid '216' becomes '226')
```

-----

## 12\. Platform Misconfiguration (Access Control Bypass)

### Explanation

[cite\_start]Applications sometimes delegate access control to the web server or platform, using rules that restrict access based on the HTTP request method[cite: 1684, 1685]. [cite\_start]If these rules are not comprehensive (e.g., they only deny `POST` requests), an attacker can often bypass them by submitting the same request parameters using an allowed method like `GET`, `HEAD`, or even a custom, unrecognized method[cite: 1696, 1706].

### Code/Example

[cite\_start]A platform rule denies `POST` requests to `/admin/createUser` for all non-admin users[cite: 1695].

  * **Blocked Request:**
    ```http
    POST /admin/createUser HTTP/1.1
    Host: wahh-app.com

    username=newadmin&role=admin
    ```
  * [cite\_start]The attacker re-sends the request using the `GET` method, with parameters in the URL query string[cite: 1697].
    ```http
    GET /admin/createUser?username=newadmin&role=admin HTTP/1.1
    Host: wahh-app.com
    ```

### Output

[cite\_start]The platform rule only checks for the `POST` method, so the `GET` request is permitted[cite: 1696]. [cite\_start]If the application code is written to handle parameters from both the body and the URL, it processes the request and creates the new administrative user, completely bypassing the intended access control[cite: 1697].

### Diagram

```ascii
+----------+                                +----------------+
| Attacker |                                |                |
+----------+                                |   Application  |
     |                                      |      Code      |
     |--- POST /admin/createUser ---> [DENIED] |                |
     |                                      +----------------+
     |     +-------------------+
     +---> | Platform Controls |
           +-------------------+
     |                                      +----------------+
     |                                      |                |
     |--- GET /admin/createUser ----> [ALLOWED]---> [PROCESSED]  | (VULNERABILITY)
     |                                      |   Application  |
                                            |      Code      |
                                            +----------------+
```

-----

## 13\. Predictable Tokens due to Time Dependency

### Explanation

[cite\_start]This vulnerability occurs when an application's token generation algorithm heavily relies on the server's time as an input[cite: 502]. [cite\_start]If there is not enough other randomness (entropy), an attacker can analyze a sequence of tokens to discover the time-based pattern and predict tokens issued to other users[cite: 503].

### Code/Example

[cite\_start]An application generates tokens with two parts: a simple incrementing ID and a timestamp in milliseconds[cite: 517, 551].

  * **Example Tokens:**
    ```
    [cite_start]3124538-1172764258718 [cite: 507]
    [cite_start]3124539-1172764259062 [cite: 508]
    ```

[cite\_start]An attacker requests tokens frequently[cite: 556]. [cite\_start]They receive token `3124545-...` and then, a moment later, token `3124553-...`[cite: 544]. [cite\_start]They know 7 tokens were issued to other users in between[cite: 545]. [cite\_start]They also know the timestamps of their own two tokens, giving them a very narrow time window (a few hundred milliseconds) to search for the missing tokens[cite: 558, 559].

### Output

[cite\_start]The attacker launches a brute-force script to test all possible millisecond values within the narrow time window for the missing incremental ID (e.g., `3124546`)[cite: 560]. [cite\_start]This allows them to quickly find the valid token for another user's active session and hijack it[cite: 561].

### Diagram

```ascii
Token Structure: [Incrementing_ID]-[Timestamp_in_ms]

Attacker's Actions:
1. Gets Token_A: 3124545-1172764260421 (at time T1)
2. Waits a moment
3. Gets Token_B: 3124553-1172764800468 (at time T2)

Attacker's Logic:
- A user (Victim) must have received token ID 3124546.
- The timestamp for that token must fall between T1 and T2.
- Brute-force `3124546-[T1...T2]` to find the valid session.
```

-----

## 14\. Disclosure of Tokens via Referer Header

### Explanation

[cite\_start]A serious vulnerability arises when applications transmit session tokens within the URL[cite: 1134]. [cite\_start]If a user clicks a link that leads to an external site, their browser will send the full URL of the page they came from—including the session token—to the external server in the `Referer` HTTP header[cite: 1143].

### Code/Example

[cite\_start]A web application's URL contains the user's session token: `http://www.ingentaconnect.com/jsessionid=akhahgdigali8`[cite: 1161]. [cite\_start]An attacker sends the victim an email containing a link to a resource on a server the attacker controls[cite: 1173]. When the victim clicks the link, their browser makes a request to the attacker's server, including the `Referer` header.

  * **Request Logged by Attacker's Server:**
    ```http
    GET /pagead/show_ads.js HTTP/1.1
    Host: pagead2.googlesyndication.com
    [cite_start]Referer: http://www.ingentaconnect.com/jsessionid=akhahgdigali8 [cite: 1161]
    ```

### Output

[cite\_start]The attacker simply has to check their web server's access logs to find the captured `Referer` header[cite: 1174]. [cite\_start]They can then extract the `jsessionid` and use it to hijack the victim's session in real-time[cite: 1175].

### Diagram

```ascii
+--------+   1. Clicks link to Attacker's site   +-----------------+
| Victim | ------------------------------------> | Attacker Server |
|        |    (Browser automatically sends     |                 |
| on App |     Referer header with token)      |                 |
+--------+   <------------------------------------ |                 |
                 2. Attacker's site responds         +-----------------+
                                                            |
                                                            | 3. Attacker reads logs,
                                                            |    steals token, and
                                                            |    hijacks session.
```

-----

## 15\. Insecure Parameter-Based Access Control

### Explanation

[cite\_start]This is a critical access control flaw where the application determines a user's permissions based on a parameter submitted by the client[cite: 1709]. [cite\_start]The application improperly trusts that the user will not tamper with this parameter (e.g., a hidden form field or a query string parameter) to escalate their own privileges[cite: 1711, 1712].

### Code/Example

A normal user discovers that when an administrator is logged in, their URLs contain an extra parameter:

  * **Administrator's URL:**
    ```
    [cite_start]https://wahh-app.com/login/home.jsp?admin=true [cite: 1714]
    ```

[cite\_start]The normal user can test this flaw by simply adding that same parameter to their own URL while browsing the site[cite: 1716].

### Output

[cite\_start]When the normal user sends a request to `.../home.jsp?admin=true`, the server-side code reads the parameter and, trusting it completely, grants the user's session full administrative rights[cite: 1716]. This allows for a trivial and complete privilege escalation.

### Diagram

```ascii
Normal User Request:
+--------+    GET /home.jsp     +---------------------+
| User   | -------------------> | Server Logic        | --> Returns Normal Page
+--------+                      | (admin param missing) |
                                  +---------------------+

Attacker's Request:
+--------+ GET /home.jsp?admin=true +---------------------+
| Attacker|---------------------->| Server Logic        | --> Returns ADMIN Page (VULNERABILITY)
+--------+                       | (finds admin=true)    |
                                   +---------------------+
```

-----

## 16\. Insecure Direct Object Reference (IDOR)

### Explanation

[cite\_start]An Insecure Direct Object Reference (IDOR) is a common and severe access control flaw[cite: 142]. [cite\_start]It occurs when an application uses a user-supplied identifier (like a document ID, user ID, or order number) to access a resource directly, but fails to perform an additional check to verify that the current user is actually authorized to access that specific resource[cite: 142, 1635].

### Example

[cite\_start]A user accesses their personal document via a URL containing a predictable, numeric identifier (`docid`)[cite: 1633].

  * **Legitimate URL for User A (accessing their own document):**
    ```
    [cite_start]https://wahh-app.com/ViewDocument.php?docid=1280149120 [cite: 1633]
    ```

[cite\_start]An attacker, logged in as User B, simply modifies the `docid` parameter in their browser to try and access other documents[cite: 141].

  * **Attacker's URL (attempting to access User A's document):**
    ```
    https://wahh-app.com/ViewDocument.php?docid=1280149120
    ```

### Output

[cite\_start]Because the application only uses the `docid` to retrieve the document and performs no ownership check, it serves User A's private document to the attacker (User B)[cite: 1635]. [cite\_start]This is a horizontal privilege escalation that leads to unauthorized information disclosure[cite: 142].

### Diagram

```ascii
+-------------+   Requests docid=123   +------------------+
| User A      | ---------------------> | Server retrieves | --> Shows User A's doc
| (Owner)     |                        | Doc 123          |
+-------------+                        +------------------+

+-------------+   Requests docid=123   +------------------+
| User B      | ---------------------> | Server retrieves | --> Shows User A's doc (VULNERABILITY)
| (Attacker)  |                        | Doc 123          |
+-------------+                        +------------------+
                                       (No ownership check)
```

-----

## 17\. Testing the Quality of Randomness with a Sequencer

### Explanation

[cite\_start]Simply looking at a token is not enough to confirm it is random[cite: 599]. [cite\_start]A rigorous method involves using statistical analysis on a large sample of tokens to identify non-random properties[cite: 601]. [cite\_start]Tools like Burp Sequencer automate this by collecting thousands of tokens and applying various statistical tests (at both the character and bit level) to measure their "effective entropy," or true randomness[cite: 608, 609].

### Example

[cite\_start]A tester configures Burp Sequencer to repeatedly make a request that issues a new session token[cite: 610]. [cite\_start]After collecting a large sample (e.g., 5,000 to 20,000 tokens), they run the analysis function[cite: 642, 643].

### Output

[cite\_start]The tool produces a report with an overall entropy score, measured in bits[cite: 648]. [cite\_start]A low score indicates that the tokens are not truly random and may be predictable, even if the pattern is not obvious[cite: 677]. [cite\_start]This quantitative result provides strong evidence of a vulnerability in the token generation algorithm[cite: 685, 686].

### Diagram

```ascii
+-------------+     1. Request New Token     +----------+
| Burp        | ----------------------------> | App Server |
| Sequencer   | <---------------------------- |            |
+-------------+     2. Receive Token         +----------+
      |
      | (Repeats thousands of times to collect sample)
      |
      V
+------------------------+     3. Analyze Sample     +-----------------+
| Statistical Analysis   | ------------------------> | Entropy Result  |
| (Character/Bit tests)  |                           | (e.g., "32 bits") |
+------------------------+                           +-----------------+
```

-----

## 18\. Vulnerable Mapping: Static and Concurrent Sessions

### Explanation

[cite\_start]This vulnerability is not in the token itself, but in the application's fundamental logic for mapping tokens to sessions[cite: 1199]. Two common flaws exist:

  * [cite\_start]**Static Tokens**: The application assigns a permanent, unchanging token to a user that is reissued on every login[cite: 1206, 1207]. If this token is ever compromised, the account is compromised forever.
  * [cite\_start]**Concurrent Sessions**: The application allows a single user account to have multiple different, valid session tokens active at the same time[cite: 1200, 1201]. [cite\_start]This allows an attacker with stolen credentials to log in without invalidating the legitimate user's session, making their presence much harder to detect[cite: 1204].

### Example

[cite\_start]To test for concurrent sessions, a tester logs into the application as "user1" from one browser (e.g., Chrome)[cite: 1226]. [cite\_start]Then, without logging out, they use a different browser (e.g., Firefox) to log in as "user1" again[cite: 1226]. [cite\_start]They then check if the original session in Chrome is still active[cite: 1227].

### Output

[cite\_start]If the tester can use both sessions at the same time, the application is vulnerable to supporting concurrent sessions[cite: 1227]. [cite\_start]This allows an attacker to use compromised credentials without the risk of being discovered by forcing the legitimate user out[cite: 1227].

### Diagram

```ascii
+-----------------+
| User Account:   |
|    "user1"      |
+-----------------+
      |
+-------------------------------------------------+
|                                                 |
V                                                 V
+---------------------+                   +---------------------+
| Session 1           |                   | Session 2           |
| (User on Chrome)    |                   | (Attacker on Firefox) |
| Token: AAA...       |                   | Token: BBB...       |
| Status: ACTIVE      |                   | Status: ACTIVE      |
+---------------------+                   +---------------------+
(Both tokens are valid and can access the account simultaneously)
```

-----

## 19\. Business Logic Exploitation in Access Control

### Explanation

[cite\_start]This is an advanced type of access control vulnerability where an attacker exploits flaws in the application's workflow or state machine[cite: 1582]. [cite\_start]The application might protect individual functions correctly but fails to enforce the intended sequence of operations[cite: 1569]. [cite\_start]This can allow an attacker to bypass a critical step, such as an approval or payment stage[cite: 1583].

### Example

[cite\_start]An e-commerce application has a multi-stage checkout process: 1. View Cart -\> 2. Enter Shipping -\> 3. Make Payment -\> 4. Confirm Order[cite: 1664]. [cite\_start]An attacker proceeds to the payment page (step 3), but instead of submitting payment, they attempt to directly browse to the final confirmation URL from step 4[cite: 1660].

### Output

[cite\_start]If the confirmation page (step 4) does not validate that the "payment successful" state was properly set for the session, it may process the order as if payment were received[cite: 1667]. [cite\_start]The attacker successfully exploits the business logic to receive products or services for free[cite: 1583].

### Diagram

```ascii
Intended Workflow:
[ Cart ] -> [ Shipping ] -> [ Payment ] -> [ Confirmation ]
                                 |
                            (State: PAID)

Attacker's Workflow (Exploit):
[ Cart ] -> [ Shipping ] -X-> [ Payment ]
     |                            ^
     |                            | (SKIPPED)
     +----------------------------+
     |
     V
[ Confirmation ]  (VULNERABILITY: Server fails to check for PAID state)
```

-----

## 20\. Reactive Session Termination (Aggressive Defense)

### Explanation

[cite\_start]This is a proactive defensive technique where an application is designed to immediately terminate a user's session upon detecting any anomalous request[cite: 1484]. [cite\_start]Instead of just returning an error, the application invalidates the user's session token and forces them to re-authenticate[cite: 1488]. [cite\_start]This defense is triggered by actions like tampering with hidden form fields, violating parameter length restrictions, or submitting input associated with common attacks like SQL injection[cite: 1486].

### Example

[cite\_start]An attacker is probing for vulnerabilities by modifying a hidden form field, changing `<input type="hidden" name="role" value="user">` to `value="admin"` and submitting the form[cite: 1486].

### Output

[cite\_start]The application's security logic detects that a read-only, hidden field was tampered with[cite: 1486]. [cite\_start]It immediately invalidates the attacker's session and redirects them to the login page[cite: 1488]. [cite\_start]This defense makes automated scanning and manual probing extremely time-consuming and frustrating for an attacker, as they must log in again after every single attempt[cite: 1488].

### Diagram

```ascii
Normal Request Flow:
+----------+     Normal Request      +--------------+
| User     | ----------------------> | App Server   | --> Returns Data
+----------+                         +--------------+

Aggressive Defense Flow:
+----------+   Malicious Request     +--------------+
| Attacker | ----------------------> | App Server   |
+----------+   (e.g., tampered       |              |
               hidden field)         | (Anomaly     |
                                     |  Detected!)  |
                                     +--------------+
                                            |
                                            V
                               +-------------------------+
                               | 1. Invalidate Session   |
                               | 2. Redirect to Login    |
                               +-------------------------+
```

-----

## 21\. Alternatives to Sessions

### Explanation

[cite\_start]Not all applications use traditional server-side sessions with a token[cite: 311]. Understanding these alternatives is key to testing. The two main alternatives are:

  * [cite\_start]**HTTP Authentication**: Uses built-in browser authentication mechanisms (Basic, Digest, NTLM)[cite: 313]. [cite\_start]The browser sends an `Authorization` header with every request after the user logs in via a native browser pop-up[cite: 314, 315]. There is no application-level session cookie.
  * **Sessionless State Mechanisms**: The application avoids storing session data on the server. [cite\_start]Instead, it bundles all state information into a large, encrypted or signed data blob and passes it back and forth with the client, usually in a hidden form field[cite: 322]. [cite\_start]A new blob may be issued with every request[cite: 334].

### Example

A tester observes that an application does not issue a `Set-Cookie` header for sessions. Instead, every form contains a large, unreadable hidden field named `APP_STATE`. The value of this field changes with every response. [cite\_start]This indicates a sessionless state mechanism[cite: 333, 334].

### Output

[cite\_start]Recognizing this pattern tells the tester that standard session attacks (like prediction, fixation, or hijacking a persistent token) will fail[cite: 337]. The attack surface shifts to the state blob itself—can it be decrypted, can its signature be broken, or can an old blob be replayed?

### Diagram

```ascii
Traditional Session Model:
+--------+   Cookie: token123   +------------------+
| Client | -------------------> | Server           |
|        |                      | (Looks up token123 |
|        |                      |  in session store) |
+--------+                      +------------------+

Sessionless State Model:
+--------+ HiddenField: [Encrypted Data Blob] +----------+
| Client | -----------------------------------> | Server   |
|        |                                      | (Decrypts|
|        | <----------------------------------- |  blob to |
|        |  New HiddenField: [New Encrypted Blob] | get state)|
+--------+                                      +----------+
```

-----

## 22\. A Multilayered Privilege Model (Defense-in-Depth)

### Explanation

[cite\_start]Robust security is not achieved with a single control; it requires a layered defense, also known as "defense-in-depth"[cite: 2144]. [cite\_start]This model enforces access controls at multiple tiers of the infrastructure, so if one layer is breached, another may still stop the attack[cite: 2146]. Key layers and control types include:

  * [cite\_start]**Programmatic Control**: Fine-grained logic explicitly coded into the application[cite: 2188, 2190].
  * [cite\_start]**Role-Based Access Control (RBAC)**: Users are assigned to roles, and permissions are granted to roles, simplifying management[cite: 2195].
  * [cite\_start]**Declarative Control**: Controls are enforced by an outer layer, like the database or application server[cite: 2209]. [cite\_start]For example, the application itself connects to the database using a low-privilege, read-only account, making it impossible for an application flaw to modify data[cite: 2206, 2212].
  * [cite\_start]**Discretionary Access Control (DAC)**: Allows users to delegate their own privileges to other users for specific resources they own[cite: 2191].

### Example

[cite\_start]An attacker finds a SQL injection vulnerability in an application's search feature and attempts to use it to run an `UPDATE` query to change their role to "admin"[cite: 2211]. [cite\_start]Although the application's programmatic controls fail due to the vulnerability, the application was designed with declarative controls: the web server process for this user's role connects to the database using a database account that has only `SELECT` (read-only) permissions[cite: 2150].

### Output

[cite\_start]The attacker's `UPDATE` statement is passed to the database, but the database itself rejects the query because the database user account does not have the required write privileges[cite: 2212]. [cite\_start]The attack is stopped by the database layer, even though the application layer was successfully breached[cite: 2211].

### Diagram

```ascii
Attacker's Request --> [ Layer 1: Application Code (Bypassed via SQLi) ]
                            |
                            V
                        [ Layer 2: Database Privileges ]
                        (App uses a read-only DB account)
                            |
                            V
                     [  Attack Blocked by Database  ]
```

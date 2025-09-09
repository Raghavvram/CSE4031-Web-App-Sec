## 1. Enable mod_cgi in Apache
- On Debian or Ubuntu based systems, run:
  ```
  sudo a2enmod cgi
  sudo systemctl restart apache2
  ```
- This activates the CGI module and restarts Apache so changes take effect.
- The CGI scripts will typically run from `/usr/lib/cgi-bin/` with proper permissions and configuration.[1][2]

## 2. Create the vulnerable CGI script
- Create a file `/usr/lib/cgi-bin/hello.cgi` with the following content:
  ```perl
  #!/usr/bin/perl
  print "Content-type: text/html\n\n";
  my $input = $ENV{'QUERY_STRING'};
  system("echo Hello $input"); # vulnerable to command injection
  ```
- Make it executable:
  ```
  sudo chmod +x /usr/lib/cgi-bin/hello.cgi
  ```
- The script reads input from the query string and passes it directly to `system()`, enabling command injection.[3][4]

## 3. Access the CGI script from a browser
- Open a browser and visit:
  ```
  http://localhost/cgi-bin/hello.cgi?name=Jagadeesh
  ```
- You should see the output like "Hello name=Jagadeesh" indicating the script is working.

## 4. Use Burp Suite to intercept and test injection
- Open Burp Suite and configure your browser to use Burp as a proxy.
- In Burp Proxy, make sure intercept is on.
- Navigate to the URL above (`http://localhost/cgi-bin/hello.cgi?name=Jagadeesh`) and intercept the request.
- Right-click the intercepted request in the Proxy → HTTP history and select "Send to Repeater".
- Go to the Repeater tab and modify the parameter to inject a command:
  ```
  name=Jagadeesh; cat /etc/passwd
  ```
- Send the request from Repeater and observe the response.
- The contents of `/etc/passwd` should be included in the response, confirming command injection vulnerability.[5][6][7]

## Summary of commands and files involved:
```bash
sudo a2enmod cgi
sudo systemctl restart apache2

sudo nano /usr/lib/cgi-bin/hello.cgi
# Paste the perl script content

sudo chmod +x /usr/lib/cgi-bin/hello.cgi
```

Browser URL:
```
http://localhost/cgi-bin/hello.cgi?name=Jagadeesh
```

Burp Suite edit in Repeater:
```
name=Jagadeesh; cat /etc/passwd
```

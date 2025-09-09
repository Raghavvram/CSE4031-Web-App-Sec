## 1. Setup LAMP Stack
- Install Apache, MySQL, and PHP on your Linux system (Ubuntu example):
  ```bash
  sudo apt update
  sudo apt install apache2 mysql-server php libapache2-mod-php php-mysql -y
  sudo systemctl start apache2
  sudo systemctl enable apache2
  sudo systemctl start mysql
  sudo systemctl enable mysql
  ```
- Confirm Apache is running by visiting `http://localhost` in a browser to see the default page.[1][2]

## 2. Create a Vulnerable PHP Script
- Place the following PHP code in `/var/www/html/users.php`:
  ```php
  <?php
  $conn = new mysqli("localhost", "root", "your_mysql_password", "testdb");
  if ($conn->connect_error) {
      die("Connection failed: " . $conn->connect_error);
  }
  $id = $_GET['id'];
  $result = $conn->query("SELECT * FROM users WHERE id='$id'");
  
  while ($row = $result->fetch_assoc()) {
      echo "User: " . $row['username'] . "<br>";
  }
  $conn->close();
  ?>
  ```
- Create the `testdb` database and `users` table with some sample data:
  ```sql
  CREATE DATABASE testdb;
  USE testdb;
  CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(50));
  INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob'), (3, 'Charlie');
  ```
- Make sure permissions are correct to serve the PHP page.[3][4]

## 3. Test the CGI PHP script in Browser
- Visit:
  ```
  http://localhost/users.php?id=1
  ```
- You should see "User: Alice" output.

## 4. Use Burp Suite to Test SQL Injection
- Configure your browser proxy to Burp Suite.
- In Burp Proxy, enable Intercept.
- Browse to the URL above.
- Intercept the HTTP GET request.
- Right-click on the request → Send to Repeater.
- In the Repeater tab, modify the parameter `id` to an SQL injection payload:
  ```
  id=1' OR '1'='1
  ```
- Send the modified request.
- Observe the response showing all users, confirming SQL injection:
  ```
  User: Alice
  User: Bob
  User: Charlie
  ```
- This proves the SQL query was manipulated to bypass intended filtering.[5][6][7]

***

### Summary of commands and file locations:

Set up database and sample data:
```sql
CREATE DATABASE testdb;
USE testdb;
CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(50));
INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob'), (3, 'Charlie');
```

PHP file location: `/var/www/html/users.php`

Browser URL for testing: `http://localhost/users.php?id=1`

Burp Suite injection payload: `id=1' OR '1'='1`

This procedure illustrates exploiting SQL Injection on a vulnerable PHP script on a LAMP stack using Burp Suite for manual testing.


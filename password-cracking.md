# Password cracking

Passwords can be brute-forced \(e.g. just iterating through different letter/number combinations\) but it is often more efficient to use a dictionary. In Kali, wordlists can be found in `/usr/share/wordlists`. Both `fasttrack` and `rockyou` are good for testing weak passwords. Many applications and services are installed with [default passwords](http://www.defaultpassword.com/), so always check for those before attempting to crack them.

## Identifying hashes

Passwords will often be hashed in databases, sometimes with a salt. If the database/application includes a salt with the password, you'll need to some research to figure out how it is used in the hashed password. For example, it might be concatenated with the password \(salt + password, password + salt\) before hashing, or it may be hashed multiple times.

Identifying hashes using hash-identifer:

```text
hash-identifier
```

## John the Ripper

John is useful for offline password cracking, with a hash stored in a text file.

Usage:

```text
john --wordlist=/usr/share/wordlists/rockyou.txt -format=Raw-MD5 /root/Desktop/john.txt
```

The `format` option is not always necessary as john does a decent job of guessing. Here's a [list of supported formats](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats).

## Hydra

Hydra is a command-line tool for online password attacks, such as website login pages and ssh. The options can be tricky, so you can use [Burp Intruder](https://support.portswigger.net/customer/portal/articles/1964020-using-burp-to-brute-force-a-login-page) as an alternative for websites. However, it seems to have trouble loading large wordlists such as rockyou.

### Websites

Hydra is useful for brute-forcing website login pages, but you'll need to [pass it the HTTP request string using Burp's proxy](https://www.hackers-arise.com/single-post/2018/02/26/Online-Password-Cracking-with-THC-Hydra-and-Burp-Suite) and parameters for success or failure.

General format for website attacks:

```text
hydra -L <username list> -p <password list> <IP Address> http-post-form "<path>:<form parameters>:<failed login message>"
```

Attack [DVWA](http://www.dvwa.co.uk/) login page:

```text
hydra -L <wordlist> -P <password list> [host] http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"
```

Attack WordPress login page with a known username, success parameter `S=` instead of failure parameter, verbose output:

```text
hydra -l [username] -P /usr/share/wordlists/rockyou.txt [host] http-post-form "/wp-admin/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:S=http%3A%2F%2F[host]%2Fwp-admin%2F" -V
```

### SSH

General usage:

```text
hydra -l root -P /usr/share/wordlists/fasttrack.txt [host] ssh
```

SSH with a non-standard port \(22022\):

```text
hydra -s 22022 -l root -P /usr/share/wordlists/fasttrack.txt [host] ssh
```

SSH with a username wordlist, non-standard port, limited threads and verbose output:

```text
hydra -s 22022 -L userlist.txt -P /usr/share/wordlists/fasttrack.txt [host] ssh -t 4  -v
```

## Hashcat

Hashcat is a very fast password-cracking tool, with [many supported formats](https://hashcat.net/wiki/doku.php?id=example_hashes).

General usage:

```text
hashcat -m 0 -a 0 -o cracked.txt target_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

* `m` is the hash format \(e.g. m 13100 is Kerberos 5\)
* `a 0` is a dictionary attack
* `o cracked.txt` is the output file for the cracked password
* `target_hashes.txt` is the hash to be cracked
* `/usr/share/wordlists/rockyou.txt` is the absolute path to the wordlist
* `--force` is something I always have to add \(think it's GPU-related\)

## GPP-decrypt

Group Policy Preferences \(GPP\) has been used in the past to allow Windows administrators to create domain policies with embedded credentials. These policies allowed administrators to set local accounts, embed credentials for the purposes of mapping drives, or perform other tasks that may otherwise require an embedded password in a script.

Unfortunately, the password that is stored in the policy is [encrypted with a known key](https://msdn.microsoft.com/en-us/library/cc422924.aspx), meaning anyone who can access the GPP [can obtain the plain text password](https://blog.rapid7.com/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage/). Since GPPs are stored on the domain controller in the SYSVOL share, this means that at a minimum all domain users can access the encrypted credentials.

Once you find and download the groups.xml file, extract the contents of `cpassword` and use gpp-decrypt:

```text
gpp-decrypt [hash]
```

## Custom wordlists

Custom wordlists are useful when targeting a specific organization or individual, to generate more relevant password lists.

### Crunch

The first tool we will look at is Crunch. Crunch is an easy to use tool for generating a custom password lists that can be used to guess passwords. These include:

* All combinations for a number of letters.
* All combinations for a range of characters followed by static text.
* Password lists based on default password ranges \(default router passwords for example\).

General usage:

```text
crunch [min length] [max length] [charset] [options]
```

Generates a password list with all possible combinations of 4 capital letters:

```text
crunch 4 4 ABCDEFGHIJKLMNOPQRSTUVWXYZ -o /root/Desktop/wordlist.txt
```

Generate a list with all combinations for 5 digits:

```text
crunch 5 5 0123456789 -o /root/Desktop/wordlist.txt
```

Generate a wordlist that contains all possible combinations with four letters followed by 1980:

```text
crunch 8 8 ABCDEFGHIJKLMNOPQRSTUVWXYZ -t @@@@1980 -o /root/Desktop/wordlist.txt
```

Use the -p option defining the charset which eliminates repeating characters or words. This is creates a wordlist using different combinations of specific words.

Generate all combinations of the words ‘Dog Cat Mouse’:

```text
crunch 1 2 -p Dog Cat Mouse -o /root/Desktop/wordlist.txt
```

### Cewl

Cewl scrapes websites for text to generate a custom password list.

Options:

* `-m` is the minimum word length for words to save to the wordlist.
* `-d` is the maximum depth the spider is allowed to scrape.
* `-o` is offsite, used to allow the spider to leave the current website to another website.
* `-w` is write to output file, specify the output file here.

Example: use Cewl on the Kali Linux website to find words with 8 letters or greater and go 1 level deep:

```text
cewl -d 1 -m 8 -w /root/Desktop/cewl.txt https://www.kali.org
```

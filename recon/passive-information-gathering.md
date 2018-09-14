# Passive information gathering

## DNS enumeration

Domain Name System \(DNS\) enumeration is the process of identifying the DNS servers and records. DNS translates human-readable hostnames into machine-readable IP addresses.

Important records for enumeration include:

* **Address \(A\)** records containing the IP addresses for domains
* **Mail Exchange \(MX\)** records containing mail addresses
* **Canonical Name \(CNAME\)** records used for aliasing domains and identifying subdomains within DNS records
* **Name Server \(NS\)** records showthe authoritative \(or main\) name server for the domain
* **State of Authority \(SOA\)** records have important information about the domain such as the primary name server, timestamp showing last update and the party responsible for the domain
* **Pointer Records \(PTR\)** map an IPv4 address to the CNAME on the host, aka ‘reverse record’ because it connects a record with an IP address to a hostname instead of the other way around
* **TXT records** may include additional information \(e.g. configuration\)

Some tools used for DNS enumeration included with Kali Linux are:

* whois
* nslookup
* host
* dig
* Fierce
* DNSenum
* DNSrecon

### Whois

A whois lookup can be used to get general information about the domain such as the registrar, domain owner, their contact information and DNS server:

```text
whois google.com
```

### Nslookup

nslookup stands for Name Server lookup, used for querying the domain name system in order to obtain DNS records:

```text
nslookup google.com
```

You can query DNS records using the option -type= followed by the DNS record type like this:

```text
nslookup -type=A google.com
```

You can use ‘any’ as DNS record type to return all DNS records for the domain:

```text
nslookup -type=any google.com
```

#### SPF Record

A Sender Policy Framework \(SPF\) record is a type of DNS record that identifies which mail servers are permitted to send email on behalf of your domain. SPF records prevent spammers from sending messages with forged ‘From’ addresses from a particular domain. A receiving mail server uses the sending domain's SPF record to check if the message comes from a legitmate server.

### Host

Host can be used to convert domain names to IP addresses and vice versa:

```text
host google.com
```

#### Zone transfers

DNS is critical component for ensuring that applications are available and work properly. For this reason, they usually have redundant/secondary servers which must be synced to each other. This replication mechanism for DNS databases \(which contain DNS records\) is known as a **zone transfer**. A zone transfer occurs when the information from the primary DNS server is replicated on one or more secondary DNS servers.

Zone transfers can unintentionally leak sensitive information to an attacker. For example, a DNS zone may reveal a complete list of all hosts for a given zone, including hostnames, providing a larger attack surface. DNS servers with zone transfers enabled to the public can reveal staging servers, business applications, VOIP servers and other assets which would not be discovered through brute force techniques. Zone transfers are typically disabled for DNS servers, but it is still worth checking with tools like **Host** or **Fierce**, just in case.

To check for zone transfer capability using host, use this command to retrieve the name server:

```text
host -t ns google.com
```

Then use the name server as an argument in the next command:

```text
host -t axfr -l google.com ns1.google.com
```

### Dig

Dig \(short for Domain Information Groupr\) is a tool to query DNS servers that works like Host.

For example, to retrieve MX records for the google.com domain:

```text
dig -t mx google.com
```

To request all records, specify `any` as parameter:

```text
dig -t any google.com
```

To test for zone transfers, use the following command: \(zonetransfer is deliberately vulnerable\)

```text
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

### Fierce

Fierce is a reconnaissance tool which uses DNS to identify targets inside and outside corporate networks.

Type `fierce -h` for a list of options and usage instructions:

```text
fierce -dns google.com
```

With this command, Fierce will attempt to locate the name servers for the given domain and perform a zone transfer on each one. It also checks for a wildcard DNS record and guesses subdomains using an internal wordlist. A custom wordlist can be specified with the following command:

```text
fierce -dns google.com –wordlist /path/to/wordlist/
```

#### Wildcard domains

A Wildcard DNS record is a DNS record that will match any request when there is no record available that explicitly matches that request. The Wildcard DNS record is usually defined using an asterisk as the first label: `*.domain.com.`

For example:

```text
www.domain.com     A      1.1.1.1

vpn.domain.com     A      1.1.1.2

test.domain.com    A      1.1.1.3

*.domain.com       A      1.1.1.1
```

Requesting the IP address for `www.domain.com` returns the IP 1.1.1.1. If we request the IP address for `vpn.domain.com` we will get 1.1.1.2 and so on. However, requesting the IP for a domain that is not explicitly defined, such as 8u1fc.domain.com, we will get the wildcard response of 1.1.1.1.

Tools like Fierce will first make a request for an unlikely subdomain \(e.g sffvfdghdf9w3534.google.com\) before guessing common names from a wordlist. If a wildcard domain exists, then every guess can theoretically come back with a positive result, but Fierce is able to distinguish between wildcard and real results and discard them.

### DNSenum

DNSenum enumerates the DNS information to discover non-contiguous IP blocks. It also attempts zone transfers on DNS:

```text
dnsenum google.com
```

### DNSrecon

DNSrecon is another automated tool for querying DNS records and attempting zone transfers.

For options, type `dnsrecon -h`:

```text
dnsrecon -d google.com
```

### Sublist3r

Sublist3r is a tool written in Python for enumerating subdomains using popular search engines to discover subdomains for a selected domain name. It can also guess subdomains using an integrated tool named **Subbrute**, which uses a wordlist to enumerate DNS records and subdomains:

```text
sublist3r -d google.com
```

To add brute forcing with Subbrute, use the `-b` option to the command and control the number of additional threads to use with the `-t` option:

```text
sublist3r -d google.com -b -t 100
```

## Email harvesting

### The Harvester

The Harvester is used for e-mail harvesting across several search engines. If an organization doesn't have a public employee directory, this can be a quick way to gather email addresses for phishing or searching for passwords in recent database dumps.

For example:

```text
theharvester -d microsoft.com -b google -l 5
```

The domain is specified by `-d` and the data source with `-b` \(Google\). Search results can be limited with the `-l` option.

### Recon-ng

Recon-ng is a Metasploit-style reconnaissance framework which can harvest emails and also check data dumps for passwords:

```text
show modules

use recon/contacts-credentials/hibp_breach

[recon-ng][default][hibp_breach] > show info

set source info@microsoft.com
```

Similar to Metasploit, you can select specific data dumps and set the source email to search.

## Search engines

### Google dorks

Google can identify subdomains for a particular website:

```text
site:msn.com -site:www.msn.com

site:*.nextcloud.com
```

To exclude a specific subdomain:

```text
site:*.nextcloud.com -site:help.nextcloud.com
```

#### Social Media

Search specific social media sites for information:

```text
site:twitter.com orgname
site:linkedin.com orgname
site:facebook.com orgname
```

#### Non-HTML documents

Search for specific filetypes on organizational websites:

```text
site:example.com filetype:pdf
```

### Shodan

To-do

## References

* [http://www.technicalinfo.net/papers/PassiveInfoPart1.html](http://www.technicalinfo.net/papers/PassiveInfoPart1.html)
* [https://blog.bugcrowd.com/discovering-subdomains](https://blog.bugcrowd.com/discovering-subdomains)


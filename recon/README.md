# Reconnaissance

## Passive information gathering \(OSINT\)

Passive information gathering is the process of collecting information about a target from public sources such as search engines, social media and organizational websites. This work is usually performed before the penetration test, or is part of the scoping exercise. The reason it is considered passive is that these activities aren't typically detectable by the target because they don't involve scanning servers or other assets. However, seemingly innocuous public information can be combined to generate wordlists, email addresses and account names for more effective phishing and password attacks.

Passive information gathering activities should be focused on identifying IP addresses, \(sub\)domains, finding external partners and services, the types of technologies used and any other useful information \(including the names of employees working at the company, e-mail addresses, websites, customers, naming conventions, E-mail & VPN systems and sometimes even passwords\).

There are many sources for passive enumeration, including:

* Google, Shodan and other search engines
* Social media such as LinkedIn, Twitter, Facebook & Instagram
* Organizational websites
* News releases
* Discussion forums
* Whois databases
* Data dumps from previous breaches

## Active information gathering

Enumeration is the process of retrieving usernames, shares, services, web directories, groups, and computers on a network to better understand the attack surface before a penetration test. A critical part of the enumeration process involves port scanning, service enumeration and OS fingerprinting. This allows an ethical hacker to identify vulnerabilities that might be exploited, such as unpatched web server software. Wherever possible, all TCP and UDP ports should be scanned, since many services can reside on higher ports, including common ones like **ssh**.


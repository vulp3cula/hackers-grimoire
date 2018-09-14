# Reconnaissance

## Passive information gathering \(OSINT\)

Passive information gathering is the process of collecting information about a target from public sources such as search engines, social media and organizational websites. This work is usually performed before the penetration test, or is part of the scoping exercise. The reason it is considered passive is that the activities aren't intrusive or highly detectable like scanning servers or other assets. 

Passive information gathering activities focus on identifying IP addresses, domains, external services, technologies used, employee names, email addresses, passwords, etc. Stuff that could help you get a foothold in the organization.

There are many sources for passive enumeration, including:

* Google, Shodan and other search engines
* Social media such as LinkedIn, Twitter, Facebook & Instagram
* Organizational websites
* News releases
* Discussion forums
* Whois databases
* Data dumps from previous breaches

## Active information gathering

Active information gathering is the processes of discovering usernames, shares, services, web directories, groups, and computers on a network to better understand the attack surface before a penetration test. It's usually more prone to detection because it involves port scanning, service enumeration and OS fingerprinting. This allows an ethical hacker to identify vulnerabilities that might be exploited, such as unpatched web server software. Enumeration should be as comprehensive as possible, for example don't forget to scan TCP, UDP and higher port ranges. Many services can reside on higher ports, including common ones like **ssh**.


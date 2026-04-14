# Python Hunt
## Quick OSINT checks for IPs and Domains during triage and investigations.

---

### About
This script queries APIs for various freely-available intelligence platforms
in order to gain important context and reputation data for IP addresses and/or
domains.

---

#### Platforms Used
* WHOIS
* VirusTotal
* AlienVault OTX
* Greynoise
* Robtex
* Shodan
* ipinfo.io


##### API Keys Required for:
* VirusTotal
* Greynoise
* Shodan

If you do not wish to create an account to get an API key for these platforms,
you can use the `-p` or `--platforms` argument to only enable the platforms you
want to use.  See Example Usage below for more information.

NOTE: All three of these APIs can be obtained with free accounts.


#### Installation and Requirements
This is built for Python 3.x.

A recent rework of this script should allow you to run this on MacOS and Linux 
without the need to install any additional packages or run in it a virtual
environment (venv).

You will need to edit the main script to include your API keys for a few
of the platforms.  Do this in the "API Key" section near the top of the code.

If you'd like to link this in your CLI $PATH, perform the following:
```bash
$ ln -s /path/to/repo/investigate.py /usr/local/bin/investigate
```
Reload your terminal (new window, log off and back on, etc) and `investigate`
should be a native command.  You can now call it by executing directly.
```bash
$ investigate
```


#### Example Usage
Python Hunt can take single IPs as command line argument with `-i` or `--ipaddress`.
```bash
$ investigate -i 95.217.163.246
```

It can also perform a lookup for domains with `-d` or `--domain` flags.
```bash
$ investigate -d apple.com
```
Finally, it can check a file for a list of IPs or Domains.
You may mix types in the file, but they must be 1 per line.
You can do this by using `-f` or `--file`.

```bash
$ investigate -f IoC_file.txt
```
Unfortunately, due to API rate limiting with some of the free APIs, you may only
look up 5 items per minute by default.
If you have paid for API keys without limits, you can ignore this.

Otherwise, you can also specify which APIs to use with the optional `-p`
or `--platforms` flag.
By default, if no platform is specified, the script will run through all
of them.

```bash
$ investigate -i 165.254.239.130 -p ipinfo
```
Or
```bash
$ investigate -f IoC_file.txt -p otx shodan
```

#### Example Output

```bash
$ investigate -i 64.95.10.243
_________________________________________

    Investigating 64.95.10.243:

    Connecting from Dallas, Texas; US.
    IP belongs to AS399629 BL Networks.


    Shodan
    ----------

    Geolocation double-check:
        Dallas, United States, TX
        Owned by BL Networks.

    Additional Shodan Info:
        OS: None
        Port(s): [80, 443, 22]
        Hostname: ['supfoundrysettlers.us']
        Last Updated: 2024-06-21T00:06:36.008929


    VirusTotal
    ----------

    Scan Stats:
    Country is US
    AS Owner is BLNWX
    Harmless: 49
    Suspicious: 2
    Malicious: 16
    Undetected: 26


    AlienVault OTX
    ----------

    Pulse Count: 5
    Reputation Score: 0
    Pulse Name(s): Malvertising Campaign Leads to Execution of Oyster Backdoor, Malware campaign attempts abuse of defender binaries, Malvertising Campaign Leads to Execution of Oyster Backdoor | Rapid7 Blog, Malvertising Campaign Leads to Execution of Oyster Backdoor | Rapid7 Blog, malvertising campaign


    Greynoise
    ----------

    IP not found in Greynoise database.


    Robtex
    ----------

    County: United States
    ASN: 10910,
    WHOIS Desc.: Carrington Capital (C01174673)
    BGP Route: 64.95.0.0/20
    Active DNS Record: None
    Active DNS History: None
    Passive DNS: None
    Passive DNS History: None

  ```

---

```bash
$ investigate -d creditkarma.com
__________________________________________________

    Investigating Domain "creditkarma.com"


    WHOIS
    ----------

    Created on 2005-08-30 02:56:23
    Expires on 2024-08-30 02:56:23
    Registrar: CSC Corporate Domains, Inc.
    Last Updated: 2023-08-27 05:34:34
    Registered in: US
    Name Servers: a1-204.akam.net, a16-64.akam.net, a28-65.akam.net, a3-67.akam.net, a4-66.akam.net, a9-66.akam.net, dns1.p04.nsone.net, dns2.p04.nsone.net, dns3.p04.nsone.net, dns4.p04.nsone.net


    VirusTotal
    ----------

    Domain Created: 2005-08-29 10:56:23
    Alexa Rank: 821
    Cisco Umbrella Rank: 11422
    Overall Reputation: 0
    Harmless: 67
    Suspicious: 0
    Malicious: 0
    Undetected: 26


    AlienVault OTX
    ----------

    No findings for this domain.

```

---

```bash
$ investigate -i 165.254.239.130 -p ipinfo robtex
_________________________________________

    Investigating 165.254.239.130:

    Connecting from Santa Monica, California; US.
    IP belongs to AS2914 NTT America, Inc..


    Robtex
    ----------

    County: United States
    ASN: 2914, NTTC-GIN-AS NTT Communications Global IP
    WHOIS Desc.: NTT America, Inc. (NTTAM-1)
    BGP Route: 165.254.0.0/16
    Active DNS Record: None
    Active DNS History: d1-6-1-1-1.a00.smtwny01.us.ce.verio.net
    Passive DNS: hc-1-us-ca-1.services.vnc.com
    Passive DNS History: None

```

---

### Thank you to the following projects
* [Python Whois](https://pypi.org/project/python-whois/)
* [VirusTotal](https://virustotal.com)
* [AlienVault](https://otx.alienvault.com)
* [Greynoise](https://viz.greynoise.io)
* [IP Info](https://ipinfo.io)
* [Shodan](https://shodan.io)
* [Robtex](https://www.robtex.com)


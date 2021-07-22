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
* Robtex
* IBM X-Force
* Shodan
* ipinfo.io


##### API Keys Required for:
* VirusTotal
* IBM X-Force
* Shodan

If you do not wish to create an account to get an API key for these platforms,
you can use the `-p` or `--platforms` argument to only enable the platforms you want
to use.  See Example Usage below for more information.


#### Installation and Requirements
This is built for Python 3.x.

Install required modules with:
```bash
python3 -m pip install -r requirements.txt
```

You will need to also edit the main script to include your API keys for a few
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
Unfortunately, due to API rate limiting with the free APIs, you may only
look up 5 items per minute by default.
If you have paid for API keys without limits,you can ignore this.

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
$ investigate -i 193.34.167.111
_________________________________________

    Investigating 193.34.167.111:

    Connecting from Utrecht, Utrecht; NL.
    IP belongs to AS62370 Snel.com B.V..


    Shodan
    ----------

    Geolocation double-check:
        Utrecht, Netherlands, 09; Owned by Snel.com B.V..


    Additional Shodan Info:
        OS: No Data
        Port(s): [80, 123, 443]
        Hostname: ['srv-1.canajambe.io']
        Last Updated: 2021-03-22T09:12:54.583341


    VirusTotal
    ----------

    Scan Stats:
    Country is not in VT dataset.
    AS Owner is not found.
    Harmless: No Data
    Suspicious: No Data
    Malicious: No Data
    Undetected: No Data


    AlienVault OTX
    ----------

    Pulse Count: 3
    Reputation Score: 0
    Pulse Name(s): New macOS malware XcodeSpy Targets Xcode Developers with EggShell Backdoor, New macOS malware XcodeSpy Targets Xcode Developers with EggShell Backdoor, New macOS malware XcodeSpy Targets Xcode Developers with EggShell Backdoor - SentinelLabs



    IBM X-Force
    ----------

    Recent Report Created: 2012-03-22T07:26:00.000Z
    IP Geolocation: Netherlands
    Reputation Score: 1
    Report Created Reason: One of the five RIRs announced a (new) location mapping of the IP.


    Robtex
    ----------

    County: Netherlands
    ASN: 62370, Snel
    WHOIS Desc.: To determine the registration information for a more specific range, please try a more specific query. If you see this object as a result of a single IP query, it means the IP address is currently in the free pool of address space managed by the RIPE NCC.
    BGP Route: 193.34.166.0/23
    Active DNS Record: hosted-by.snelis.com
    Active DNS History: None
    Passive DNS: None
    Passive DNS History: ns2.hartelust.com, ns2.pernillasart.com, ns2.vesconet.com

  ```

---

```bash
$ investigate -d creditkarma.com
__________________________________________________

    Investigating Domain "creditkarma.com"


    WHOIS
    ----------

    Created on 2005-08-30 02:56:23
    Expires on 2021-08-30 02:56:23
    Registrar: CSC Corporate Domains, Inc.
    Last Updated: 2019-04-15 21:04:38
    Registered in: US
    Name Servers: ns1.p16.dynect.net, ns2.p16.dynect.net, ns3.p16.dynect.net, ns4.p16.dynect.net


    VirusTotal
    ----------

    Domain Created: 2005-08-29 10:56:23
    Alexa Rank: 355
    Cisco Umbrella Rank: 24496
    Overall Reputation: 0
    Harmless: 75
    Suspicious: None.
    Malicious: None.
    Undetected: 7


    AlienVault OTX
    ----------

    Pulse Count: 1
    Reputation Score: No Data
    Pulse Name(s): xdgcdn.com -  cdn-me.com - squatting - phishing - icloud - itunes - music - inaudible - bluetooth - nfc - hacking the human


    IBM X-Force
    ----------

    Name: Credit Karma
    Score: 1
    Description: A free credit and financial management platform
    Categories: Financial Services / Insurance / Real Estate, Banking

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

#### Thank you to the following projects
* [Python Whois](https://pypi.org/project/python-whois/)
* [VirusTotal](https://virustotal.com)
* [AlienVault](https://otx.alienvault.com)
* [IP Info](https://ipinfo.io)
* [Shodan](https://shodan.io)
* [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
* [Robtex](https://www.robtex.com)


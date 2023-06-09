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
* BGPView
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
$ investigate -i 82.117.252.141
_________________________________________

    Investigating 82.117.252.141:

    Connecting from Miami, Florida; US.
    IP belongs to AS204957 GREEN FLOID LLC.
        

    Shodan
    ----------

    Geolocation double-check:
        Miami, United States, FL
        Owned by Green Floid LLC.

    Additional Shodan Info:
        OS: None
        Port(s): [3000, 5985, 3389, 5357]
        Hostname: ['dedic-chertoganov123-1110631.hosted-by-itldc.com']
        Last Updated: 2023-06-07T23:23:22.165526
            

    VirusTotal
    ----------

    Scan Stats:
    Country is US
    AS Owner is Green Floid LLC
    Harmless: 67
    Suspicious: 0
    Malicious: 0
    Undetected: 20
            

    AlienVault OTX
    ----------

    Pulse Count: 9
    Reputation Score: 0
    Pulse Name(s): #StopRansomware: CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit Vulnerability, InQuest - 08-06-2023, StopRansomware: CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit Vulnerability, StopRansomware: CL0P Ransomware  Gang Exploits  CVE-2023-34362 MOVEit Vulnerability, #StopRansomware: CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit Vulnerability | CISA, #StopRansomware: CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit Vulnerability | CISA, InQuest - 07-06-2023, #StopRansomware: CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit Vulnerability, #StopRansomware: CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit Vulnerability | CISA
                

    IBM X-Force
    ----------

    Recent Report Created: 2012-03-22T07:26:00.000Z
    IP Geolocation: No Data.
    Reputation Score: 1
    Report Created Reason: One of the five RIRs announced a (new) location mapping of the IP.
            

    BGPView
    ----------

    PTR Record: dedic-chertoganov123-1110631.hosted-by-itldc.com
    Network Block: 82.117.252.0/22
        IP: 82.117.252.0
        CIDR: 22
    Date Allocated: 2009-05-19 00:00:00

```    

```bash
$ investigate -d ef0h.com
__________________________________________________

    Investigating Domain "ef0h.com"


    WHOIS
    ----------

    Created on 2023-03-01 14:47:07
    Expires on 2024-03-01 14:47:07
    Registrar: Tucows Domains Inc.
    Last Updated: 2023-04-07 17:53:45
    Registered in: KN
    Name Servers: 1-you.njalla.no, 2-can.njalla.in, 3-get.njalla.fo
        

    VirusTotal
    ----------

    Domain Created: 2023-02-28 07:00:00
    Alexa Rank: No Data.
    Cisco Umbrella Rank: No Data.
    Overall Reputation: 0
    Harmless: 54
    Suspicious: 0
    Malicious: 12
    Undetected: 21
            

    AlienVault OTX
    ----------

    Pulse Count: 12
    Reputation Score: No Data.
    Pulse Name(s): CryptoClippy is Evolving to Pilfer Even More Financial Data, InQuest - 08-06-2023, Malware - Malware Domain Feed V2 - November 03 2020, InQuest - 07-06-2023, InQuest - 06-06-2023, InQuest - 05-06-2023, InQuest - 04-06-2023, InQuest - 03-06-2023, InQuest - 02-06-2023, InQuest - 01-06-2023, InQuest - 31-05-2023, InQuest - 30-05-2023
                    

    IBM X-Force
    ----------

    Domain not in X-Force database
            

```

---

```bash
$ investigate.py -i 134.209.101.105 -p ipinfo otx vt                                                            2 ↵
_________________________________________

    Investigating 134.209.101.105:

    Connecting from Singapore, Singapore; SG.
    IP belongs to AS14061 DigitalOcean, LLC.
        

    VirusTotal
    ----------

    Scan Stats:
    Country is SG
    AS Owner is DIGITALOCEAN-ASN
    Harmless: 57
    Suspicious: 1
    Malicious: 11
    Undetected: 18
            

    AlienVault OTX
    ----------

    No findings for this IP.
                

```

---

#### Thank you to the following projects
* [Python Whois](https://pypi.org/project/python-whois/)
* [VirusTotal](https://virustotal.com)
* [AlienVault](https://otx.alienvault.com)
* [IP Info](https://ipinfo.io)
* [Shodan](https://shodan.io)
* [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)
* [BGPView](https://bgpview.io/)


#!/usr/bin/env python3

"""
Script to assist in investigations by collecting IP data from various sources.
"""

import argparse
from datetime import datetime

import requests
import shodan
import whois

# API Keys
# API Keys are required for Shodan, VirusTotal, and IBM X-Force
# Register with them here:
# https://shodan.io
# https://virustotal.com
# https://exchange.xforce.ibmcloud.com/

SHODAN_API = "[YOUR API KEY HERE]"
VT_API = "[YOUR API KEY HERE]"
# X-Force API is not actually the API key, but the base64 value of the API Key
# and the API Password.  Do a test at the following documentation site to get
# the value from the cURL request:
# https://api.xforce.ibmcloud.com/doc/#IP_Reputation_get_ipr_ip
XFORCE_API = "[YOUR API KEY HERE]"

# Platforms
ALIENVAULT_OTX = "otx"
IBM_X_FORCE = "x-force"
IPINFO_IO = "ipinfo"
ROBTEX = "robtex"
SHODAN = "shodan"
VIRUSTOTAL = "vt"
WHOIS = "whois"
PLATFORMS = {
    ALIENVAULT_OTX,
    IBM_X_FORCE,
    IPINFO_IO,
    ROBTEX,
    SHODAN,
    VIRUSTOTAL,
    WHOIS,
}
RATELIMITED_PLATFORMS = {
    ROBTEX,
    VIRUSTOTAL,
}


def main():
    """
    Defining main parser for arguments passed to the script.
    """

    parser = argparse.ArgumentParser(
        description="Investigate an IP address or Domain for available OSINT."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ipaddress", help="IP to investigate.")
    group.add_argument("-d", "--domain", help="Domain to investigate.")
    group.add_argument(
        "-f",
        "--file",
        help="File containing a list of IPs (1 per line, up to 5 if "
        "using VirusTotal or Robtex due to API ratelimiting).",
    )
    parser.add_argument(
        "-p",
        "--platforms",
        nargs="+",
        default=PLATFORMS,
        choices=PLATFORMS,
    )
    args = parser.parse_args()

    if args.ipaddress:
        ip_check(args.ipaddress, args.platforms)
    elif args.domain:
        domain_check(args.domain, args.platforms)
    elif args.file:
        targets_processed_count = 0
        is_ratelimited = bool(set(args.platforms).intersection(RATELIMITED_PLATFORMS))
        with open(args.file) as file:
            for target in file:
                if targets_processed_count > 5:
                    print("Stopping due to API ratelimits.")
                    break
                clean = target.strip()
                kind = clean.replace(".", "").replace(":", "").replace("/", "")
                # TODO: Not a gret check for IP address VS domain
                # "abc123.com" will be skipped for example
                if kind.isdigit():
                    if is_ratelimited:
                        targets_processed_count += 1
                    ip_check(clean, args.platforms)
                elif kind.isalpha():
                    if is_ratelimited:
                        targets_processed_count += 1
                    domain_check(clean, args.platforms)
                else:
                    print(f"Skipping {clean}, can't determine the type.")


# Start of IP Check functions


def geo_info(target):
    """
    Basic geolocation and IP ownership information.
    """
    data = requests.get(f"https://ipinfo.io/{target}/json").json()
    print(
        """_________________________________________

    Investigating {}:

    Connecting from {}, {}; {}.
    IP belongs to {}.
        """.format(
            data.get("ip", "IP Not Found."),
            data.get("city", "Not Found."),
            data.get("region", "Not Found."),
            data.get("country", "Not Found."),
            data.get("org", "Not Found."),
        )
    )


def shodan_check(target):
    """
    Double check geo and org information with Shodan, as well as pull
    additional information on the host.
    """
    print(
        """
    Shodan
    ----------"""
    )
    try:
        data = shodan.Shodan(SHODAN_API).host(target)
    except shodan.APIError as error:
        print(f"    {error}")
    else:
        print(
            """
    Geolocation double-check:
        {}, {}, {}
        Owned by {}.""".format(
                data.get("city", "No Data."),
                data.get("country_name", "No Data"),
                data.get("region_code", "No Data."),
                data.get("org", "No Data."),
            )
        )
        print(
            """
    Additional Shodan Info:
        OS: {}
        Port(s): {}
        Hostname: {}
        Last Updated: {}
            """.format(
                data.get("os", "No Data."),
                data.get("ports", "No Data."),
                data.get("hostnames", "No Data."),
                data.get("last_update", "No Data"),
            )
        )


def vt_ip_check(target):
    """
    Checks VirusTotal for known malicious actions/malware associated with the IP.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    headers = {"x-apikey": VT_API}
    response = requests.get(url, headers=headers)
    attributes = response.json().get("data", {}).get("attributes", {})
    last_analysis = attributes.get("last_analysis_stats", {})
    print(
        """
    VirusTotal
    ----------"""
    )
    if response.status_code == 200:
        print(
            """
    Scan Stats:
    Country is {}
    AS Owner is {}
    Harmless: {}
    Suspicious: {}
    Malicious: {}
    Undetected: {}
            """.format(
                attributes.get("country", "Not Found"),
                attributes.get("as_owner", "Not Found"),
                last_analysis.get("harmless", "None."),
                last_analysis.get("suspicious", "None."),
                last_analysis.get("malicious", "None."),
                last_analysis.get("undetected", "None."),
            )
        )
    else:
        print(
            """
    Error:
    VirusTotal Response Code {}""".format(
                response.status_code
            )
        )


def av_otx(target):
    """
    Checks IP to see if it shows up in any "pulse", which is a crowdsourced
    datafeed for malware/malicious action.
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}"
    response = requests.get(url)
    data = response.json()

    print(
        """
    AlienVault OTX
    ----------"""
    )
    if response.status_code == 200:
        pulse_count = data.get("pulse_info", {}).get("count")
        if pulse_count > 0:
            pulse_name = [item["name"] for item in data["pulse_info"]["pulses"]]

            print(
                """
    Pulse Count: {}
    Reputation Score: {}
    Pulse Name(s): {}
                """.format(
                    pulse_count,
                    data.get("reputation", "No Data"),
                    ", ".join(pulse_name) if pulse_name else "No Data",
                )
            )

        elif pulse_count == 0:
            print(
                """
    No findings for this IP.
                """
            )
    else:
        print(
            """
    Error: OTX response code: {}""".format(
                response.status_code
            )
        )


def robtex(target):
    """
    Robtex provides acitve and passive DNS data, as well as BGP routing data.
    """
    # Robtex doesn't accept the Python UA for some reason, so we need to set a
    # custom UA.  This one is mimicking Firefox 90 on MacOS Big Sur.
    # Change if desired.
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:90.0) Gecko/20100101 Firefox/90.0"
    }
    data = requests.get(
        f"https://freeapi.robtex.com/ipquery/{target}", headers=headers
    ).json()
    status = data["status"]
    print(
        """
    Robtex
    ----------"""
    )
    if status == "ok":
        active_dns = [hit["o"] for hit in data.get("act", [])]
        active_hist = [hit["o"] for hit in data.get("acth", [])]
        passive_dns = [hit["o"] for hit in data.get("pas", [])]
        passive_hist = [hit["o"] for hit in data.get("pash", [])]
        print(
            """
    County: {}
    ASN: {}, {}
    WHOIS Desc.: {}
    BGP Route: {}
    Active DNS Record: {}
    Active DNS History: {}
    Passive DNS: {}
    Passive DNS History: {}
                """.format(
                data.get("country", "No Data."),
                data.get("as", "No Data."),
                data.get("asname", "No Data."),
                data.get("whoisdesc", "No Data."),
                data.get("bgproute", "No Data."),
                ", ".join(active_dns) if active_dns else "None",
                ", ".join(active_hist) if active_hist else "None",
                ", ".join(passive_dns) if passive_dns else "None",
                ", ".join(passive_hist) if passive_hist else "None",
            )
        )
    elif status == "ratelimited":
        print(
            """
    API Rate Limit reached. Try again soon.
        """
        )
    else:
        print(
            """
    Robtex has no records.
        """
        )


def xforce_ip(target):
    """
    Checking IBM's X-Force Echange for crowdsourced intelligence on the IP.
    """
    url = f"https://api.xforce.ibmcloud.com/ipr/{target}"
    headers = {
        "Accept": "application/json",
        "Authorization": "Basic {}".format(XFORCE_API),
    }
    response = requests.get(url=url, headers=headers)
    print(
        """
    IBM X-Force
    ----------"""
    )
    if response.status_code == 200:
        data = response.json()
        print(
            """
    Recent Report Created: {}
    IP Geolocation: {}
    Reputation Score: {}
    Report Created Reason: {}
            """.format(
                data.get("history", {})[0].get("created", "No Data."),
                data.get("history", {})[0].get("country", "No Data."),
                data.get("history", {})[0].get("score", "No Data"),
                data.get("history", {})[0].get("reasonDescription", "No Data."),
            )
        )
    else:
        print(
            """
    X-Force Response Code: {}
            """.format(
                response.status_code
            )
        )


# Start of Domain Check functions


def whois_lookup(target):
    """
    Basic WHOIS data lookup. Uses https://github.com/DannyCork/python-whois/
    """
    try:
        domain = whois.query(target)
        if domain is None:
            print("Domain not found in WHOIS")
            name = "Not Found."
            created = "No Data."
            expires = "No Data."
            updated = "No Data."
            reg = "No Data."
            country = "No Data."
            nameservers = None
            ns_clean = None
        else:
            name = domain.name
            created = domain.creation_date
            expires = domain.expiration_date
            updated = domain.last_updated
            reg = domain.registrar
            country = domain.registrant_country
            nameservers = domain.name_servers
            ns_clean = set(server.strip() for server in nameservers)
    except AttributeError as error:
        print(error)
    else:
        print(
            """__________________________________________________

    Investigating Domain "{}"


    WHOIS
    ----------

    Created on {}
    Expires on {}
    Registrar: {}
    Last Updated: {}
    Registered in: {}
    Name Servers: {}
        """.format(
                name if name else "No Data",
                created if created else "No Data",
                expires if expires else "No Data",
                reg if reg else "No Data",
                updated if updated else "No Data",
                country if country else "No Data",
                ", ".join(sorted(list(ns_clean))) if ns_clean else "No Data",
            )
        )


def vt_domain_check(target):
    """
    Checks VirusTotal for known malicious actions/malware associated with the Domain.
    """
    url = f"https://www.virustotal.com/api/v3/domains/{target}"
    headers = {"x-apikey": VT_API}
    response = requests.get(url, headers=headers)
    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})
    rank = data.get("data", {}).get("attributes", {}).get("popularity_ranks", {})
    last_analysis = (
        data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    )
    creation_date = attributes.get("creation_date")
    print(
        """
    VirusTotal
    ----------"""
    )
    if response.status_code == 200:
        print(
            """
    Domain Created: {}
    Alexa Rank: {}
    Cisco Umbrella Rank: {}
    Overall Reputation: {}
    Harmless: {}
    Suspicious: {}
    Malicious: {}
    Undetected: {}
            """.format(
                datetime.fromtimestamp(creation_date).strftime("%Y-%m-%d %I:%M:%S")
                if creation_date
                else "None",
                rank.get("Alexa", {}).get("rank", "No Data."),
                rank.get("Cisco Umbrella", {}).get("rank", "No Data."),
                attributes.get("reputation", "No Data."),
                last_analysis.get("harmless", "None."),
                last_analysis.get("suspicious", "None."),
                last_analysis.get("malicious", "None."),
                last_analysis.get("undetected", "None."),
            )
        )
    else:
        print(
            """
    Error:
    VirusTotal Response Code {}""".format(
                response.status_code
            )
        )


def av_otx_domain(target):
    """
    Checks Domain to see if it shows up in any "pulse", which is a crowdsourced
    datafeed for malware/malicious action.
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}"
    response = requests.get(url)
    data = response.json()
    pulse_count = data.get("pulse_info", {}).get("count", "No Data")
    print(
        """
    AlienVault OTX
    ----------"""
    )
    if response.status_code == 200:
        if pulse_count > 0:
            try:
                pulse_name = [item["name"] for item in data["pulse_info"]["pulses"]]
            except TypeError as error:
                print(error)
            print(
                """
    Pulse Count: {}
    Reputation Score: {}
    Pulse Name(s): {}
                    """.format(
                    pulse_count,
                    data.get("reputation", "No Data."),
                    ", ".join(pulse_name) if pulse_name else "No Data",
                )
            )
        elif pulse_count == 0:
            print(
                """
    No findings for this domain.
                    """
            )
    else:
        print(
            """
    Error: OTX Response Code {}
            """.format(
                response.status_code
            )
        )


def xforce_domain(target):
    """
    Checking IBM's X-Force Echange for crowdsourced intelligence on the domain.
    """
    url = "https://api.xforce.ibmcloud.com/url/{}".format(target)
    headers = {
        "Accept": "application/json",
        "Authorization": "Basic {}".format(XFORCE_API),
    }
    response = requests.get(url=url, headers=headers)
    data = response.json()
    print(
        """
    IBM X-Force
    ----------"""
    )

    if response.status_code == 200:
        try:
            categories = data["result"]["cats"].keys()
        except TypeError as error:
            print(error)
        else:
            application = data.get("result", {}).get("application", {})
            print(
                """
    Name: {}
    Score: {}
    Description: {}
    Categories: {}
                """.format(
                    application.get("name", "Not Found."),
                    data.get("result", {}).get("score", "Not Found"),
                    application.get("description", "Not Found."),
                    ", ".join(categories),
                )
            )
    elif response.status_code == 404:
        print(
            """
    Domain not in X-Force database
            """
        )
    else:
        print(
            """
    Error: X-Force Response Code: {}
            """.format(
                response.status_code
            )
        )


def ip_check(target, platforms):
    """
    Collection of all IP check functions to run.
    """
    if IPINFO_IO in platforms:
        geo_info(target)
    if SHODAN in platforms:
        shodan_check(target)
    if VIRUSTOTAL in platforms:
        vt_ip_check(target)
    if ALIENVAULT_OTX in platforms:
        av_otx(target)
    if IBM_X_FORCE in platforms:
        xforce_ip(target)
    if ROBTEX in platforms:
        robtex(target)


def domain_check(target, platforms):
    """
    Collection of all Domain check functions to run.
    """
    if WHOIS in platforms:
        whois_lookup(target)
    if VIRUSTOTAL in platforms:
        vt_domain_check(target)
    if ALIENVAULT_OTX in platforms:
        av_otx_domain(target)
    if IBM_X_FORCE in platforms:
        xforce_domain(target)


if __name__ == "__main__":
    main()

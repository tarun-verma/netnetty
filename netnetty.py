import argparse
from whois import whois
from typing import Dict, Any
from google import genai
import re
from pprint import pprint
import dns.resolver
import os

"""
TODO:
- lots of cleanup and handling corner cases (like api key)
- write some integration/unit tests
- to close: can be easily pulled and deployed
"""

# Set up gemini to generate summaries
client = genai.Client(api_key=os.getenv("GEMINI_KEY"))
chat = client.chats.create(model="gemini-2.5-flash")

# Set up the prompt to summarise whois data
prompt = "Read all the interesting information from the following WHOIS text and present a concise (at most a few sentences) summary to me with just the relevant info and what you think about it. Text:"

record_types = {
    "NONE",
    "A",
    "NS",
    "MD",
    "MF",
    "CNAME",
    "SOA",
    "MB",
    "MG",
    "MR",
    "NULL",
    "WKS",
    "PTR",
    "HINFO",
    "MINFO",
    "MX",
    "TXT",
    "RP",
    "AFSDB",
    "X25",
    "ISDN",
    "RT",
    "NSAP",
    "NSAP-PTR",
    "SIG",
    "KEY",
    "PX",
    "GPOS",
    "AAAA",
    "LOC",
    "NXT",
    "SRV",
    "NAPTR",
    "KX",
    "CERT",
    "A6",
    "DNAME",
    "OPT",
    "APL",
    "DS",
    "SSHFP",
    "IPSECKEY",
    "RRSIG",
    "NSEC",
    "DNSKEY",
    "DHCID",
    "NSEC3",
    "NSEC3PARAM",
    "TLSA",
    "HIP",
    "CDS",
    "CDNSKEY",
    "CSYNC",
    "SPF",
    "UNSPEC",
    "EUI48",
    "EUI64",
    "TKEY",
    "TSIG",
    "IXFR",
    "AXFR",
    "MAILB",
    "MAILA",
    "ANY",
    "URI",
    "CAA",
    "TA",
    "DLV",
}

ipv4_pattern = re.compile(
    r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


class NetNetty:
    def __init__(self, host) -> None:
        self.host = host
        self.hostinfo = whois(host)
        if not bool(ipv4_pattern.match(host)):
            self.records = dict()

    def get_info(self) -> Dict["str", Any]:
        self.infodict = dict()
        org_pattern = r"(Organization):\s*(.*)"  # Use this to parse through WHOIS text, in case we can't get org name directly from whois dict
        org_name = self.hostinfo["org"]
        org_mails = self.hostinfo["emails"]
        org_ns = self.hostinfo["name_servers"]

        if not org_name:
            org_name = re.findall(org_pattern, self.hostinfo.text)[0][1]
            if not org_name:
                org_name = "No org name found!"

        if not org_mails:
            org_mails = "No email addresses found!"

        if not org_ns:
            org_ns = "No name servers found!"

        self.infodict["Org Name"] = org_name
        self.infodict["Org Emails"] = org_mails
        self.infodict["Org NameServers"] = org_ns

        return self.infodict

    def llm_summary(self) -> str:
        query = prompt + f"\n\n{self.hostinfo.text}"
        try:
            response = chat.send_message(query)
            return str(response.text)
        except Exception as e:
            error = f"An unexpected error occurred during API call: {e} \n Raw API response text: {response.text}"
            return error

    def get_records(self) -> Dict["str", Any]:
        for record in record_types:
            try:
                answers = dns.resolver.resolve(self.host, record)
                for rdata in answers:
                    self.records[record] = rdata.to_text()
            except Exception:
                pass  # or pass
        return self.records


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Look up relevant info for an IP or a hostname"
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("-i", "--ip", help="the IP you want to look up info for.")
    group.add_argument(
        "-host", "--hostname", help="the hostname you want to look up info for."
    )
    parser.add_argument(
        "-s", "--summary", action="store_true", help="flag to enable LLM summary."
    )
    parser.add_argument(
        "-r",
        "--record",
        help="specify a particular DNS record type to look up (e.g., A, MX, NS). Requires -host | --hostname.",
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="dump all DNS records for a hostname. Requires -host | --hostname.",
    )

    args = parser.parse_args()

    if args.record and not args.hostname:
        parser.error("--record can only be used when --hostname is provided!")

    if args.all and not args.hostname:
        parser.error("--all can only be used when --hostname is provided!")

    if args.ip:
        information = NetNetty(args.ip)
        pprint(information.get_info(), indent=4, sort_dicts=False)
    elif args.hostname:
        information = NetNetty(args.hostname)
        records = information.get_records()

        if args.record:
            try:
                value = records[args.record]
                print(f"{args.record}: {value}")
            except KeyError:
                print(f"No record found for {args.record} query!")
        if args.all:
            pprint(records, indent=4, sort_dicts=False)
    if args.summary:
        pprint(information.llm_summary(), indent=4, sort_dicts=False)

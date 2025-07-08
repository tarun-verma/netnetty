import argparse
from whois import whois
from typing import Dict, Any
from google import genai
import json
import re
from pprint import pprint
import dns.resolver


client = genai.Client(api_key="AIzaSyCF6ezrbk36o4gCArMCzbMM5xap7jpQA0c")

record_types = {
    'NONE', 'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR', 'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP', 'AFSDB', 'X25', 'ISDN', 'RT', 'NSAP', 'NSAP-PTR', 'SIG', 'KEY', 'PX', 'GPOS', 'AAAA', 'LOC', 'NXT', 'SRV', 'NAPTR', 'KX', 'CERT', 'A6', 'DNAME', 'OPT', 'APL', 'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 'TLSA', 'HIP', 'CDS', 'CDNSKEY', 'CSYNC', 'SPF', 'UNSPEC', 'EUI48', 'EUI64', 'TKEY', 'TSIG', 'IXFR', 'AXFR', 'MAILB', 'MAILA', 'ANY', 'URI', 'CAA', 'TA', 'DLV'
}

ipv4_pattern = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

chat = client.chats.create(
    model="gemini-2.5-flash"
)

class NetNetty:
    def __init__(self, hostinfo) -> None:
        self.host = hostinfo
        self.hostinfo = whois(hostinfo)

    def get_info(self) -> Dict["str", Any]:
        self.infodict = dict()

        org_pattern = r"(Organization):\s*(.*)" # Use this to parse through WHOIS text, in case we can't get org name directly from whois dict
        org_name = self.hostinfo["org"]
        org_mails = self.hostinfo["emails"]
        org_ns = self.hostinfo["name_servers"]

        if not org_name:
            org_name = re2.findall(org_pattern, self.hostinfo.text)[0][1]
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
        prompt = f"Read all the interesting information from the following WHOIS text and present a one paragraph summary to me with just the relevant info and what you think about it. Here's the text:\n\n{self.hostinfo.text}"
        try:
            response = chat.send_message(prompt)
            return response.text
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON response from API: {e}")
            print(f"Raw API response text: {response.text}")
            return "None"  # Return an empty dict or handle error as appropriate
        except Exception as e:
            print(f"An unexpected error occurred during API call: {e}")
            return "None"

    def get_records(self):
        for record in record_types:
            try:
                answers = dns.resolver.query(self.host, record)
                for rdata in answers:
                    print(record, ':', rdata.to_text())
            except Exception as e:
                print(e)  # or pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Look up relevant info for an IP or a hostname"
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("-i", "--ip", help="the IP you want to look up info for")
    group.add_argument("-host", "--hostname", help="the hostname you want to look up info for")
    parser.add_argument("-s", "--summary", action="store_true", help="flag to enable LLM summary")
    args = parser.parse_args()

    if args.ip:
        information = NetNetty(args.ip)
        pprint(information.get_info(), indent=4, sort_dicts=False)
    elif args.hostname:
        information = NetNetty(args.hostname)
        print(information.get_records())

    if args.summary:
        print(information.llm_summary())

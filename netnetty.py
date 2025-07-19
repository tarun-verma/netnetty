import os
import sys
import time
import threading
import argparse
import whois
from typing import Dict, Any
from types import SimpleNamespace
from google import genai
import re
import dns.resolver

# Set up gemini to generate summaries
client = genai.Client(api_key=os.getenv("GEMINI_KEY"))
chat = client.chats.create(model="gemini-2.5-flash")

# Set up the prompt to summarise whois data
prompt = "Read all the interesting information from the following WHOIS text; present a three bullet point summary in short sentences about all the important info. Text:"

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
        try:
            self.hostinfo = whois.whois(host)
        except whois.parser.PywhoisError:
            self.hostinfo = SimpleNamespace(text="No whois info exists")
        if not bool(ipv4_pattern.match(host)):
            self.records = dict()

    def get_info(self) -> Dict["str", Any]:
        self.infodict = dict()
        org_pattern = r"(Organization):\s*(.*)"  # Use this to parse through WHOIS text, in case we can't get org name directly from whois dict

        if not (org_name := self.hostinfo.get("org")):
            if not (matches := re.findall(org_pattern, self.hostinfo.text)):
                org_name = "None"
            else:
                org_name = matches[0][1]

        org_mails = self.hostinfo.get("emails")
        org_ns = self.hostinfo.get("name_servers")

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

    def _animate(self, stop_event): # helper function to make the wait for DNS record processing easier
        """Displays a simple loading animation in the console."""
        animation_chars = ['|', '/', '-', '\\']
        idx = 0
        while not stop_event.is_set():
            char = animation_chars[idx % len(animation_chars)]
            # \r moves the cursor to the beginning of the line
            sys.stdout.write(f'\r{char} performing DNS lookup for all possible records...')
            sys.stdout.flush()
            time.sleep(0.1)
            idx += 1
        # Clean up the line after finishing
        sys.stdout.write('\r' + ' ' * 25 + '\r')
        sys.stdout.flush()


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
        whois_info = information.get_info()
        for k in whois_info:
            print(f"{k}: {whois_info[k]}")
    elif args.hostname:
        information = NetNetty(args.hostname)
        stop_animation = threading.Event()
        animation_thread = threading.Thread(target=information._animate, args=(stop_animation,), daemon=True)
        animation_thread.start()
        record_processing_thread = threading.Thread(target=information.get_records)
        record_processing_thread.start()
        record_processing_thread.join()
        stop_animation.set()

        print("\nLookup complete! ✅\n")

        if args.record:
            try:
                records = information.records
                value = records[args.record]
                print(f"{args.record}: {value}")
            except KeyError:
                print(f"No record found for {args.record} query!")
        if args.all:
            records = information.records
            for record in records:
                print(f"{record}: {records[record]}")
    if args.summary:
        points_list = information.llm_summary().split('\n')[-3:]
        print("\nGemini generated summary:")
        for points in points_list:
            print(points)

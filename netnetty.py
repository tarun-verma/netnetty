import argparse
from whois import whois
from typing import Dict, Any
from google import genai
import json
import re2

client = genai.Client(api_key="")
chat = client.chats.create(
    model="gemini-2.5-flash"
)

class NetNetty:
    def __init__(self, hostinfo) -> None:
        self.hostinfo = whois(hostinfo)
        self.infodict = dict()

    def get_info(self) -> Dict["str", Any]:
        org_pattern = r"(Organization):\s*(.*)"
        org_name = self.hostinfo["org"]
        org_mails = self.hostinfo["emails"]
        org_ns = self.hostinfo["name_servers"]

        if not org_name:
            org_name = re2.findall(org_pattern, self.hostinfo.text)[0][1]

        if not org_mails:
            org_mails = "No email addresses found!"

        if not org_ns:
            org_ns = "No NameServers found!"

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
            return None  # Return an empty dict or handle error as appropriate
        except Exception as e:
            print(f"An unexpected error occurred during API call: {e}")
            return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", help="the IP you want to look up info for")
    parser.add_argument("-host", "--hostname", help="the hostname you want to look up info for")
    parser.add_argument("-sum", "--summary", help="presents an LLM summary for whois info")
    args = parser.parse_args()

    if args.ip:
        information = NetNetty(args.ip)
    elif args.hostname:
        information = NetNetty(args.hostname)
    else:
        print("Please provide one of ip or hostname!")
        exit(-1)

    print(information.get_info())

    if args.summary:
        print(information.llm_summary())

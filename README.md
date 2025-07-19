# NetNetty

## Overview

NetNetty is intended to be a command-line tool designed for network reconnaissance. It provides a simple way to gather information about hostnames and IP addresses. Key features include performing `whois` lookups, fetching various DNS records, and generating an AI-powered summary of the collected data using the Google Gemini API.

This is largely me entertaining some urges to experiment with LLMs and figure out how they can better my tools (I'm bearish at the moment). I might or might not try to improve this tool to make it more useful and faster, but I've written this mostly for myself.

## Features

-   **WHOIS Lookup**: Get detailed `whois` registration data for any domain or IP address.
-   **DNS Record Retrieval**: Fetch a wide range of DNS records, including `A`, `MX`, `NS`, `TXT`, and more.
-   **AI-Powered Summaries**: Utilizes the Google Gemini API to generate a concise, three-point summary of the `whois` information, highlighting the most important details.
-   **Flexible Options**: Supports lookups for both hostnames and IP addresses, with flags to specify desired DNS records or get a full DNS dump.

## Prerequisites

Before you begin, ensure you have the following installed and configured:

-   **Python**: Version 3.12 or newer.
-   **Gemini API Key**: This tool requires an API key from Google AI Studio. You can obtain one [here](https://aistudio.google.com/app/apikey).

## Setup and Installation

1.  **Clone the Repository**
    ```sh
    git clone https://github.com/your-username/netnetty.git
    cd netnetty
    ```

2.  **Create a Virtual Environment**
    It's highly recommended to use a virtual environment to manage dependencies.
    ```sh
    python3 -m venv venv
    source venv/bin/activate
    ```
    On Windows, use:
    ```sh
    venv\Scripts\activate
    ```

3.  **Install Dependencies**
    Install all the required Python packages using `pip`:
    ```sh
    pip install -r requirements.txt
    ```

4.  **Set Environment Variable**
    You must set your Gemini API key as an environment variable named `GEMINI_KEY`.
    ```sh
    export GEMINI_KEY='your_api_key_here'
    ```
    To make this permanent, add the line to your shell's configuration file (e.g., `.zshrc`, `.bash_profile`).

## Usage

The script `netnetty.py` is the entry point for the tool. You can use it with various flags to perform different lookups.

### Basic IP Lookups

-   **Look up an IP address:**
    ```sh
    (netnetty) λ  netnetty git:(main) python3 netnetty.py -i 151.101.20.116
    Org Name: Fastly, Inc. (SKYCA-3)
    Org Emails: ['abuse@fastly.com', 'rir-admin@fastly.com', 'noc@fastly.com']
    Org NameServers: None
    ```

### DNS Record Lookups

-   **Get all available DNS records for a hostname:**
    *(This requires the `--hostname` flag.)*
    ```sh
    (netnetty) λ  netnetty git:(main) python3 netnetty.py -host google.com -a
    | performing DNS lookup for all possible records...
    Lookup complete! ✅

    CAA: 0 issue "pki.goog"
    AAAA: 2a00:1450:4009:c17::8b
    TXT: "cisco-ci-domain-verification=47c38bc8c4b74b7233e9053220c1bbe76bcc1cd33c7acf7acd36cd6a5332004b"
    MX: 10 smtp.google.com.
    SOA: ns1.google.com. dns-admin.google.com. 784870257 900 900 1800 60
    A: 142.251.30.101
    NS: ns4.google.com.
    ```


-   **Get a specific DNS record for a hostname:**
    *(This requires the `--hostname` flag.)*
    ```sh
    (netnetty) λ  netnetty git:(main) python3 netnetty.py -host google.com -r SOA
    / performing DNS lookup for all possible records...
    Lookup complete! ✅

    SOA: ns1.google.com. dns-admin.google.com. 784524134 900 900 1800 60
    ```

### AI-Generated Summary

-   **Get a summary for a hostname or IP:**
    Add the `--summary` or `-s` flag to any lookup command to receive a Gemini-generated summary of the `whois` data.
    ```sh
    (netnetty) λ  netnetty git:(main) python3 netnetty.py -host google.com -s
    - performing DNS lookup for all possible records...
    Lookup complete! ✅


    Gemini generated summary:
    *   The domain google.com is owned by Google LLC and was originally created on September 15, 1997.
    *   It is currently managed by MarkMonitor, Inc. and is set to expire on September 13, 2028.
    *   The domain is heavily secured with multiple status codes preventing any unauthorized deletion, transfer, or updates.
    ```

    ```sh
    (netnetty) λ  netnetty git:(main) python3 netnetty.py --ip 1.1.1.1 -s
    Org Name: One Registry
    Org Emails: None
    Org NameServers: ['auth.g1-dns.one', 'auth.g1-dns.com']

    Gemini generated summary:
    *   The domain "one.one" was created on May 20, 2015, and is set to expire on May 20, 2026.
    *   It is registered to "One Registry", based in Denmark (dk).
    *   The domain utilizes "auth.g1-dns.one" and "auth.g1-dns.com" as its name servers and has DNSSEC enabled.
    ```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

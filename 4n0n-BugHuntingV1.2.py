"""MIT License

Copyright (c) 2025 EAST TIMOR GHOST SECURITY (Mr.Y)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""


import aiohttp
import asyncio
import urllib.parse
import logging
import json
import re
import time
import signal
import sys

# Setup logging
logging.basicConfig(filename='vulnerability_scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = []

    async def fetch(self, session, url):
        """Fetch the URL and return the response text and status."""
        try:
            async with session.get(url) as response:
                return await response.text(), response.status
        except Exception as e:
            logging.error(f"Error fetching {url}: {e}")
            return None, None

    async def check_rce(self, payload):
        """Check for Remote Code Execution vulnerabilities."""
        test_url = f"{self.target_url}?cmd={urllib.parse.quote(payload)}"
        async with aiohttp.ClientSession() as session:
            response_text, status = await self.fetch(session, test_url)
            if status == 200:
                # Heuristic detection for RCE
                if "expected_output" in response_text:  # Replace with expected output
                    self.results.append(f"[!] Potential RCE vulnerability found with payload: {payload}")
                elif re.search(r'error|exception|failed|command not found', response_text, re.IGNORECASE):
                    self.results.append(f"[!] Possible RCE vulnerability indicated by error message with payload: {payload}")

    async def check_lfi(self, payload):
        """Check for Local File Inclusion vulnerabilities."""
        test_url = f"{self.target_url}?file={urllib.parse.quote(payload)}"
        async with aiohttp.ClientSession() as session:
            response_text, status = await self.fetch(session, test_url)
            if status == 200:
                # Heuristic detection for LFI
                if "expected_content" in response_text:  # Replace with expected content
                    self.results.append(f"[!] Potential LFI vulnerability found with payload: {payload}")
                elif re.search(r'error|exception|failed|no such file or directory', response_text, re.IGNORECASE):
                    self.results.append(f"[!] Possible LFI vulnerability indicated by error message with payload: {payload}")

    async def check_directory_traversal(self, payload):
        """Check for Directory Traversal vulnerabilities."""
        test_url = f"{self.target_url}?file={urllib.parse.quote(payload)}"
        async with aiohttp.ClientSession() as session:
            response_text, status = await self.fetch(session, test_url)
            if status == 200:
                # Heuristic detection for Directory Traversal
                if "expected_content" in response_text:  # Replace with expected content
                    self.results.append(f"[!] Potential Directory Traversal vulnerability found with payload: {payload}")
                elif re.search(r'error|exception|failed|no such file or directory', response_text, re.IGNORECASE):
                    self.results.append(f"[!] Possible Directory Traversal vulnerability indicated by error message with payload: {payload}")

    async def check_session_hijacking(self):
        """Check for Session Hijacking vulnerabilities."""
        if "session_id" in self.target_url:
            self.results.append("[!] Potential Session Hijacking vulnerability found: Session ID in URL")

    async def check_insecure_data_storage(self):
        """Check for Insecure Data Storage vulnerabilities."""
        if "password" in self.target_url or "token" in self.target_url:
            self.results.append("[!] Potential Insecure Data Storage vulnerability found: Sensitive data in URL")

    async def check_xxe(self, payload):
        """Check for XML External Entity vulnerabilities."""
        headers = {'Content-Type': 'application/xml'}
        data = f"""<?xml version="1.0"?>
        <!DOCTYPE foo [
            <!ENTITY xxe SYSTEM "{payload}">
        ]>
        <foo>&xxe;</foo>"""
        async with aiohttp.ClientSession() as session:
            async with session.post(self.target_url, data=data, headers=headers) as response:
                response_text = await response.text()
                if response.status == 200:
                    # Heuristic detection for XXE
                    if "expected_content" in response_text:  # Replace with expected content
                        self.results.append(f"[!] Potential XXE vulnerability found with payload: {payload}")
                    elif re.search(r'error|exception|failed', response_text, re.IGNORECASE):
                        self.results.append(f"[!] Possible XXE vulnerability indicated by error message with payload: {payload}")

    async def check_ssrf(self, payload):
        """Check for Server-Side Request Forgery vulnerabilities."""
        test_url = f"{self.target_url}?url={urllib.parse.quote(payload)}"
        async with aiohttp.ClientSession() as session:
            response_text, status = await self.fetch(session, test_url)
            if status == 200:
                # Heuristic detection for SSRF
                if "expected_content" in response_text:  # Replace with expected content
                    self.results.append(f"[!] Potential SSRF vulnerability found with payload: {payload}")
                elif re.search(r'error|exception|failed', response_text, re.IGNORECASE):
                    self.results.append(f"[!] Possible SSRF vulnerability indicated by error message with payload: {payload}")

    async def check_xssi(self):
        """Check for Cross-Site Script Inclusion vulnerabilities."""
        test_url = f"{self.target_url}?script=example.js"  # Adjust the parameter as needed
        async with aiohttp.ClientSession() as session:
            response_text, status = await self.fetch(session, test_url)
            if status == 200:
                # Heuristic detection for XSSI
                if "sensitive_data" in response_text:  # Replace with expected content
                    self.results.append("[!] Potential XSSI vulnerability found: Sensitive data included in script.")

    async def run_checks(self, check_type, payloads):
        """Run the specified checks based on the type and payloads."""
        tasks = []
        for payload in payloads:
            if check_type == 'RCE':
                tasks.append(self.check_rce(payload))
            elif check_type == 'LFI':
                tasks.append(self.check_lfi(payload))
            elif check_type == 'Directory Traversal':
                tasks.append(self.check_directory_traversal(payload))
            elif check_type == 'XXE':
                tasks.append(self.check_xxe(payload))
            elif check_type == 'SSRF':
                tasks.append(self.check_ssrf(payload))
        await asyncio.gather(*tasks)

    def save_results(self):
        """Save the results to a JSON file."""
        with open('scan_results.json', 'w') as f:
            json.dump(self.results, f, indent=4)

def load_payloads(file_path):
    """Load payloads from a file."""
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] File {file_path} not found.")
        return []

def print_with_delay(text, delay=0.03):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()  # New line after the text

# Display banner with animation
banner = """
\033[1;33m███████╗ █████╗ ███████╗████████╗    ████████╗██╗███╗   ███╗ ██████╗ ██████╗      ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███████╗███████╗ ██████╗
\033[1;33m██╔════╝██╔══██╗██╔════╝╚══██╔══╝    ╚══██╔══╝██║████╗ ████║██╔═══██╗██╔══██╗    ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝
\033[1;37m█████╗  ███████║███████╗   ██║          ██║   ██║██╔████╔██║██║   ██║██████╔╝    ██║  ███╗███████║██║   ██║███████╗   ██║   ███████╗█████╗  ██║     
\033[1;37m██╔══╝  ██╔══██║╚════██║   ██║          ██║   ██║██║╚██╔╝██║██║   ██║██╔══██╗    ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ╚════██║██╔══╝  ██║     
\033[1;31m███████╗██║  ██║███████║   ██║          ██║   ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║    ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ███████║███████╗╚██████╗
\033[1;31m╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝          ╚═╝   ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝
\033[0m
"""

# Author info
author_info = "Code by EAST TIMOR GHOST SECURITY (Mr.Y) version: 1.2"

# Calculate the position to center the author info
banner_lines = banner.strip().split('\n')
max_length = max(len(line) for line in banner_lines)
centered_author_info = author_info.center(max_length)

# Combine banner and author info
full_banner = "\n".join(banner_lines) + "\n" + centered_author_info + "\n"

# Print banner and author info with animation
print_with_delay(full_banner)

# Function to handle Ctrl+C
def signal_handler(sig, frame):
    print("\n", end="")
    print_with_delay("THANK YOU FOR USING THE TOOLS", delay=0.05)
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)
        
async def main():
    print("=============SELECT YOUR OPTIONS================")
    print("[1] Check for RCE vulnerabilities")
    print("[2] Check for LFI vulnerabilities")
    print("[3] Check for Directory Traversal vulnerabilities")
    print("[4] Check for Session Hijacking vulnerabilities")
    print("[5] Check for Insecure Data Storage vulnerabilities")
    print("[6] Check for XML External Entity (XXE) vulnerabilities")
    print("[7] Check for Server-Side Request Forgery (SSRF) vulnerabilities")
    print("[8] Check for Cross-Site Script Inclusion (XSSI) vulnerabilities")

    choice = input("Enter your choice (1-8): ")
    target_url = input("Enter the target URL: ")
    scanner = VulnerabilityScanner(target_url)

    if choice == '1':
        rce_payloads_file = input("Enter the path to the RCE payload file: ")
        rce_payloads = load_payloads(rce_payloads_file)
        await scanner.run_checks('RCE', rce_payloads)
    elif choice == '2':
        lfi_payloads_file = input("Enter the path to the LFI payload file: ")
        lfi_payloads = load_payloads(lfi_payloads_file)
        await scanner.run_checks('LFI', lfi_payloads)
    elif choice == '3':
        dir_traversal_payloads_file = input("Enter the path to the Directory Traversal payload file: ")
        dir_traversal_payloads = load_payloads(dir_traversal_payloads_file)
        await scanner.run_checks('Directory Traversal', dir_traversal_payloads)
    elif choice == '4':
        await scanner.check_session_hijacking()
    elif choice == '5':
        await scanner.check_insecure_data_storage()
    elif choice == '6':
        xxe_payloads_file = input("Enter the path to the XXE payload file: ")
        xxe_payloads = load_payloads(xxe_payloads_file)
        await scanner.run_checks('XXE', xxe_payloads)
    elif choice == '7':
        ssrf_payloads_file = input("Enter the path to the SSRF payload file: ")
        ssrf_payloads = load_payloads(ssrf_payloads_file)
        await scanner.run_checks('SSRF', ssrf_payloads)
    elif choice == '8':
        await scanner.check_xssi()
    else:
        print("[ERROR] Invalid choice. Exiting.")
        return

    # Save results to a JSON file
    scanner.save_results()
    print("[INFO] Scan completed. Results saved to scan_results.json.")

if __name__ == "__main__":
    asyncio.run(main())

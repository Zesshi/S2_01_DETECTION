# Installation Instructions:
# ⚠️ You encountered an "externally-managed-environment" error. To resolve this, use one of the following methods:
#
# ✅ **Preferred Method (Virtual Environment):**
# python3 -m venv venv
# source venv/bin/activate  # On Windows: venv\\Scripts\\activate
# pip install python-nmap
#
# ✅ **Alternative (System Package):**
# sudo apt install python3-nmap
#
# ✅ **Override (Not Recommended):**
# pip install python-nmap --break-system-packages
#
# ✅ **Using pipx (Recommended for CLI Tools):**
# sudo apt install pipx
# pipx install python-nmap
#
# Make sure Nmap is installed:
# Linux (Debian/Ubuntu): sudo apt install nmap
# macOS: brew install nmap
# Windows: Download from https://nmap.org/download.html and add it to PATH.

import socket
import subprocess
import requests
import json
import paramiko

try:
    import nmap
except ImportError:
    print("[!] The 'python-nmap' library is not installed.")
    print("Use one of the following:")
    print(" - Virtual env: python3 -m venv venv && source venv/bin/activate && pip install python-nmap")
    print(" - System pkg: sudo apt install python3-nmap")
    print(" - Override: pip install python-nmap --break-system-packages")
    exit(1)

# Function to scan a host for open ports and services
def scan_host(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-sV -sU -O --script vulners')

        report = {}
        for host in nm.all_hosts():
            report[host] = {
                'os_detection': nm[host].get('osmatch', 'OS detection failed'),
                'open_ports': {},
                'vulnerabilities': []
            }

            for proto in nm[host].all_protocols():
                for port, service in nm[host][proto].items():
                    report[host]['open_ports'][port] = {
                        'protocol': proto,
                        'state': service['state'],
                        'name': service['name'],
                        'product': service.get('product', 'N/A'),
                        'version': service.get('version', 'N/A'),
                    }

                    if 'script' in service and 'vulners' in service['script']:
                        report[host]['vulnerabilities'].append(service['script']['vulners'])

        return report

    except Exception as e:
        return f"[!] Failed to scan host: {e}"

# Function to check SSL/TLS security
def check_ssl(target, port=443):
    try:
        result = subprocess.run(["sslscan", f"{target}:{port}"], capture_output=True, text=True)
        output = result.stdout.strip()
        return output if output else "[!] No SSL info retrieved."
    except FileNotFoundError:
        return "[!] sslscan not found. Install with 'sudo apt install sslscan'."
    except Exception as e:
        return f"[!] SSL check failed: {e}"

# Function to perform directory and file enumeration
def enumerate_directories(target):
    common_paths = ['/admin', '/login', '/.git', '/backup', '/test']
    discovered = []

    for path in common_paths:
        try:
            response = requests.get(f"http://{target}{path}", timeout=3)
            if response.status_code in [200, 301, 302]:
                discovered.append(path)
        except requests.RequestException:
            continue

    return discovered or "No common directories found."

# Function to check for weak credentials (basic check)
def check_weak_credentials(target, port=22):
    weak_users = ['admin', 'root', 'user']
    weak_passwords = ['admin', '1234', 'password', 'root']

    for user in weak_users:
        for password in weak_passwords:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(target, port, username=user, password=password, timeout=3)
                client.close()
                return f"Weak credentials found: {user}/{password}"
            except paramiko.AuthenticationException:
                print(f"[!] Authentication failed for {user}/{password}")
                continue  # Move to next attempt
            except paramiko.ssh_exception.SSHException as e:
                return f"[!] SSH Error: {str(e)}"
            except EOFError:
                return "[!] SSH Error: Connection closed unexpectedly."
    return "No weak credentials detected."


# Main execution
def main():
    target_host = input("Enter target host (IP or domain): ")

    print("\n[+] Scanning host...")
    scan_results = scan_host(target_host)

    print("\n[+] Checking SSL...")
    ssl_results = check_ssl(target_host)

    print("\n[+] Enumerating directories...")
    directory_enumeration = enumerate_directories(target_host)

    print("\n[+] Checking weak credentials...")
    weak_creds = check_weak_credentials(target_host)

    print("\n=== REPORT ===")
    print(json.dumps(scan_results, indent=2))
    print("\nSSL Check:", ssl_results)
    print("\nDirectory Enumeration:", directory_enumeration)
    print("\nWeak Credentials:", weak_creds)

if __name__ == "__main__":
    main()

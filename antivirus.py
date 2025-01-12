import os
import sys
import logging
from datetime import datetime
import time

# Set script directory
script_dir = os.getcwd()

# Define log directories and files
log_directory = os.path.join(script_dir, "log")
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Separate log files for different purposes
console_log_file = os.path.join(log_directory, "antivirusconsole.log")
application_log_file = os.path.join(log_directory, "antivirus.log")
stdin_log_file = os.path.join(log_directory, "antivirusstdin.log")

# Configure logging for application log
logging.basicConfig(
    filename=application_log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

class DualStream:
    """Custom stream that writes to both the console and a file."""
    def __init__(self, file_path):
        self.console = sys.__stdout__  # Original stdout (console)
        self.file = open(file_path, "w", encoding="utf-8", errors="ignore")

    def write(self, message):
        # Write to the console and file
        self.console.write(message)
        self.file.write(message)
        self.console.flush()
        self.file.flush()

    def flush(self):
        # Ensure that both streams are flushed
        self.console.flush()
        self.file.flush()

# Redirect stdout and stderr to our DualStream class
sys.stdout = DualStream(console_log_file)
sys.stderr = DualStream(console_log_file)

# Redirect stdin to a log file (keeping as original behavior)
sys.stdin = open(stdin_log_file, "w+", encoding="utf-8", errors="ignore")

# Logging for application initialization
logging.info("Application started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# Start timing total duration
total_start_time = time.time()

# Start individual module timing
start_time = time.time()
import whois
print(f"whois module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from urllib.parse import urlparse
print(f"urlib.parse.urlparse module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import socket
print(f"socket module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import csv
print(f"csv module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from googlesearch import search
print(f"googlesearch.search module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ipaddress
print(f"ipaddress module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import requests
print(f"requests module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import re
print(f"re module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QMessageBox, QStackedWidget, QInputDialog, QTextEdit, QLineEdit
print(f"PySide6.QtWidgets modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtCore import QThread, Signal
print(f"PySide6.QtCore modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtGui import QIcon
print(f"PySide6.QtGui.QIcon module loaded in {time.time() - start_time:.6f} seconds")

# Calculate and print total time
total_end_time = time.time()
total_duration = total_end_time - total_start_time
print(f"Total time for all imports: {total_duration:.6f} seconds")

website_rules_dir = os.path.join(script_dir, "website")
excluded_rules_dir = os.path.join(script_dir, "excluded")
excluded_rules_path = os.path.join(excluded_rules_dir, "excluded_rules.txt")
ipv4_addresses_path = os.path.join(website_rules_dir, "IPv4Malware.txt")
ipv4_whitelist_path = os.path.join(website_rules_dir, "IPv4Whitelist.txt")
ipv6_addresses_path = os.path.join(website_rules_dir, "IPv6Malware.txt")
ipv6_whitelist_path = os.path.join(website_rules_dir, "IPv6Whitelist.txt")
# Define all website file paths
malware_domains_path = os.path.join(website_rules_dir, "MalwareDomains.txt")
malware_domains_mail_path = os.path.join(website_rules_dir, "MalwareDomainsMail.txt")
phishing_domains_path = os.path.join(website_rules_dir, "PhishingDomains.txt")
abuse_domains_path = os.path.join(website_rules_dir, "AbuseDomains.txt")
mining_domains_path = os.path.join(website_rules_dir, "MiningDomains.txt")
spam_domains_path = os.path.join(website_rules_dir, "SpamDomains.txt")
whitelist_domains_path = os.path.join(website_rules_dir, "WhiteListDomains.txt")
whitelist_domains_mail_path = os.path.join(website_rules_dir, "WhiteListDomainsMail.txt")
# Define corresponding subdomain files
malware_sub_domains_path = os.path.join(website_rules_dir, "MalwareSubDomains.txt")
malware_mail_sub_domains_path = os.path.join(website_rules_dir, "MalwareSubDomainsMail.txt")
phishing_sub_domains_path = os.path.join(website_rules_dir, "PhishingSubDomains.txt")
abuse_sub_domains_path = os.path.join(website_rules_dir, "AbuseSubDomains.txt")
mining_sub_domains_path = os.path.join(website_rules_dir, "MiningSubDomains.txt")
spam_sub_domains_path = os.path.join(website_rules_dir, "SpamSubDomains.txt")
whitelist_sub_domains_path = os.path.join(website_rules_dir, "WhiteListSubDomains.txt")
whitelist_mail_sub_domains_path = os.path.join(website_rules_dir, "WhiteListSubDomainsMail.txt")
urlhaus_path = os.path.join(website_rules_dir, "urlhaus.txt")
antivirus_list_path = os.path.join(script_dir, "hosts", "antivirus_list.txt")
antivirus_domains_data = []
ipv4_addresses_signatures_data = []
ipv6_addresses_signatures_data = []
ipv4_whitelist_data = []
ipv6_whitelist_data = []
urlhaus_data = []
malware_domains_data = []
malware_domains_mail_data = []
phishing_domains_data = []
abuse_domains_data = []
mining_domains_data = []
spam_domains_data = []
whitelist_domains_data = []
whitelist_domains_mail_data = []
malware_sub_domains_data = []
malware_mail_sub_domains_data = []
phishing_sub_domains_data = []
abuse_sub_domains_data = []
mining_sub_domains_data = []
spam_sub_domains_data = []
whitelist_sub_domains_data = []
whitelist_mail_sub_domains_data = []
# Scanned entities with "_general" suffix
scanned_urls_general = []
scanned_domains_general = []
scanned_ipv4_addresses_general = []
scanned_ipv6_addresses_general = []

IPv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'  # Simple IPv4 regex
IPv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'  # Simple IPv6 regex

antivirus_style = """
QWidget {
    background-color: #2b2b2b;
    color: #e0e0e0;
    font-family: Arial, sans-serif;
    font-size: 14px;
}

QPushButton {
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                                stop:0.2 #007bff, stop:0.8 #0056b3);
    color: white;
    border: 2px solid #007bff;
    padding: 4px 10px;  /* Adjusted padding */
    border-radius: 8px;  /* Adjusted border-radius */
    min-width: 250px;  /* Adjusted min-width */
    font-weight: bold;
    text-align: center;
    qproperty-iconSize: 16px;
}

QPushButton:hover {
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                                stop:0.2 #0056b3, stop:0.8 #004380);
    border-color: #0056b3;
}

QPushButton:pressed {
    background: qradialgradient(cx:0.5, cy:0.5, radius:0.5, fx:0.5, fy:0.5,
                                stop:0.2 #004380, stop:0.8 #003d75);
    border-color: #004380;
}

QFileDialog {
    background-color: #2b2b2b;
    color: #e0e0e0;
}
"""

def load_website_data():
    global ipv4_addresses_signatures_data, ipv4_whitelist_data, ipv6_addresses_signatures_data, ipv6_whitelist_data, urlhaus_data, malware_domains_data, malware_domains_mail_data, phishing_domains_data, abuse_domains_data, mining_domains_data, spam_domains_data, whitelist_domains_data, whitelist_domains_mail_data, malware_sub_domains_data, malware_mail_sub_domains_data, phishing_sub_domains_data, abuse_sub_domains_data, mining_sub_domains_data, spam_sub_domains_data, whitelist_sub_domains_data, whitelist_mail_sub_domains_data

    try:
        # Load IPv4 addresses
        with open(ipv4_addresses_path, 'r') as ip_file:
            ipv4_addresses_signatures_data = ip_file.read().splitlines()
        print("IPv4 Addresses loaded successfully!")
    except Exception as ex:
        print(f"Error loading IPv4 Addresses: {ex}")

    try:
        # Load IPv4 whitelist
        with open(ipv4_whitelist_path, 'r') as whitelist_file:
            ipv4_whitelist_data = whitelist_file.read().splitlines()
        print("IPv4 Whitelist loaded successfully!")
    except Exception as ex:
        print(f"Error loading IPv4 Whitelist: {ex}")

    try:
        # Load IPv6 addresses
        with open(ipv6_addresses_path, 'r') as ipv6_file:
            ipv6_addresses_signatures_data = ipv6_file.read().splitlines()
        print("IPv6 Addresses loaded successfully!")
    except Exception as ex:
        print(f"Error loading IPv6 Addresses: {ex}")

    try:
        # Load IPv6 whitelist
        with open(ipv6_whitelist_path, 'r') as whitelist_file:
            ipv6_whitelist_data = whitelist_file.read().splitlines()
        print("IPv6 Whitelist loaded successfully!")
    except Exception as ex:
        print(f"Error loading IPv6 Whitelist: {ex}")
        ipv6_whitelist_data = []

    try:
        # Load URLhaus data
        urlhaus_data = []
        with open(urlhaus_path, 'r') as urlhaus_file:
            reader = csv.DictReader(urlhaus_file)
            for row in reader:
                urlhaus_data.append(row)
        print("URLhaus data loaded successfully!")
    except Exception as ex:
        print(f"Error loading URLhaus data: {ex}")

    try:
        # Load malware domains
        with open(malware_domains_path, 'r') as domains_file:
            malware_domains_data = domains_file.read().splitlines()
        print("Malware domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Malware domains: {ex}")
        malware_domains_data = []

    try:
        # Load malware domains email path
        with open(malware_domains_mail_path, 'r') as mail_domains_file:
            malware_domains_mail_data = mail_domains_file.read().splitlines()
        print("Malware email domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Malware email domains: {ex}")
        malware_domains_mail_data = []

    try:
        # Load phishing domains
        with open(phishing_domains_path, 'r') as domains_file:
            phishing_domains_data = domains_file.read().splitlines()
        print("Phishing domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Phishing domains: {ex}")
        phishing_domains_data = []

    try:
        # Load abuse domains
        with open(abuse_domains_path, 'r') as domains_file:
            abuse_domains_data = domains_file.read().splitlines()
        print("Abuse domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Abuse domains: {ex}")
        abuse_domains_data = []

    try:
        # Load mining domains
        with open(mining_domains_path, 'r') as domains_file:
            mining_domains_data = domains_file.read().splitlines()
        print("Mining domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Mining domains: {ex}")
        mining_domains_data = []

    try:
        # Load spam domains
        with open(spam_domains_path, 'r') as domains_file:
            spam_domains_data = domains_file.read().splitlines()
        print("Spam domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Spam domains: {ex}")
        spam_domains_data = []

    try:
        # Load whitelist domains
        with open(whitelist_domains_path, 'r') as domains_file:
            whitelist_domains_data = domains_file.read().splitlines()
        print("Whitelist domains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Whitelist domains: {ex}")
        whitelist_domains_data = []

    try:
        # Load Malware subdomains
        with open(malware_sub_domains_path, 'r') as file:
            malware_sub_domains_data = file.read().splitlines()
        print("Malware subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Malware subdomains: {ex}")
        malware_sub_domains_data = []

    try:
        # Load Malware mail subdomains
        with open(malware_mail_sub_domains_path, 'r') as file:
            malware_mail_sub_domains_data = file.read().splitlines()
        print("Malware mail subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Malware mail subdomains: {ex}")
        malware_mail_sub_domains_data = []

    try:
        # Load Phishing subdomains
        with open(phishing_sub_domains_path, 'r') as file:
            phishing_sub_domains_data = file.read().splitlines()
        print("Phishing subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Phishing subdomains: {ex}")
        phishing_sub_domains_data = []

    try:
        # Load Abuse subdomains
        with open(abuse_sub_domains_path, 'r') as file:
            abuse_sub_domains_data = file.read().splitlines()
        print("Abuse subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Abuse subdomains: {ex}")
        abuse_sub_domains_data = []

    try:
        # Load Mining subdomains
        with open(mining_sub_domains_path, 'r') as file:
            mining_sub_domains_data = file.read().splitlines()
        print("Mining subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Mining subdomains: {ex}")
        mining_sub_domains_data = []

    try:
        # Load Spam subdomains
        with open(spam_sub_domains_path, 'r') as file:
            spam_sub_domains_data = file.read().splitlines()
        print("Spam subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Spam subdomains: {ex}")
        spam_sub_domains_data = []

    try:
        # Load Whitelist subdomains
        with open(whitelist_sub_domains_path, 'r') as file:
            whitelist_sub_domains_data = file.read().splitlines()
        print("Whitelist subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Whitelist subdomains: {ex}")
        whitelist_sub_domains_data = []

    try:
        # Load Whitelist mail subdomains
        with open(whitelist_mail_sub_domains_path, 'r') as file:
            whitelist_mail_sub_domains_data = file.read().splitlines()
        print("Whitelist mail subdomains loaded successfully!")
    except Exception as ex:
        print(f"Error loading Whitelist mail subdomains: {ex}")
        whitelist_mail_sub_domains_data = []

    print("All domain and ip address files loaded successfully!")

load_website_data()

# Function to check if the IP is a local IP address
def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

# Check for Discord webhook URLs and invite links (including Canary)
def contains_discord_code(decompiled_code):
    """
    Check if the decompiled code contains a Discord webhook URL, Canary webhook URL, or a Discord invite link.
    """
    # Regular expressions for Discord links
    discord_webhook_pattern = r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
    discord_canary_webhook_pattern = r'https://canary\.discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
    discord_invite_pattern = r'https://discord\.gg/[A-Za-z0-9]+'

    # Search for matches
    discord_webhook_matches = re.findall(discord_webhook_pattern, decompiled_code)
    discord_canary_webhook_matches = re.findall(discord_canary_webhook_pattern, decompiled_code)
    discord_invite_matches = re.findall(discord_invite_pattern, decompiled_code)

    # Logging results
    if discord_webhook_matches:
        logging.warning(f"Malicious Discord webhook URLs detected: {discord_webhook_matches}")
        return True

    if discord_canary_webhook_matches:
        logging.warning(f"Malicious Discord Canary webhook URLs detected: {discord_canary_webhook_matches}")
        return True

    if discord_invite_matches:
        logging.info(f"Discord invite links detected: {discord_invite_matches}")

    return False

def scan_code_for_links(decompiled_code):
    """
    Scan the decompiled code for domains, URLs, and IP addresses, removing duplicates.
    Returns a tuple (True, "No malicious or whitelisted URLs, domains, or IPs detected.") if no issues are found,
    or (False, reason) if any issues are detected, using categories like "malicious", "whitelisted", or "unknown".
    """
    try:
        # Scan for URLs
        urls = set(re.findall(r'https?://[^\s/$.?#].[^\s]*', decompiled_code))
        for url in urls:
            result, reason = scan_url_general(url)
            if not result:
                return False, f"Malicious URL detected: {reason}"

        # Scan for domains using urlparse
        for domain in urls:
            parsed_url = urlparse(domain)
            domain_name = parsed_url.netloc  # Extract the domain from the URL
            result, reason = scan_domain_general(domain_name)
            if not result:
                return False, f"Malicious domain detected: {reason}"

        # Scan for IP addresses (IPv4)
        ipv4_addresses = set(re.findall(r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', decompiled_code))
        for ip in ipv4_addresses:
            result, reason = scan_ip_address_general(ip)
            if not result:
                return False, f"Malicious IPv4 address detected: {reason}"

        # Scan for IP addresses (IPv6)
        ipv6_addresses = set(re.findall(r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}', decompiled_code))
        for ip in ipv6_addresses:
            result, reason = scan_ip_address_general(ip)
            if not result:
                return False, f"Malicious IPv6 address detected: {reason}"

        # If no issues are found
        return True, "No malicious or whitelisted URLs, domains, or IPs detected."

    except Exception as ex:
        logging.error(f"Error scanning code for links: {ex}")
        return False, f"Error scanning code for links: {ex}"

# Updated generalized scan functions to return True/False with reason for success or failure
def scan_domain_general(domain):
    try:
        # Convert domain to lowercase for consistent comparison
        domain_lower = domain.lower()

        if domain_lower in scanned_domains_general:
            logging.info(f"Domain {domain_lower} has already been scanned.")
            return True, "Already scanned"  # No issue found, continue scanning

        scanned_domains_general.append(domain_lower)  # Add to the scanned list
        logging.info(f"Scanning domain: {domain_lower}")

        # Check against spam subdomains
        if any(domain_lower == spam_sub_domain or domain_lower.endswith(f".{spam_sub_domain}") for spam_sub_domain in spam_sub_domains_data):
            logging.warning(f"Spam subdomain detected: {domain_lower}")
            return False, f"Spam subdomain detected: {domain_lower}"

        # Check against mining subdomains
        if any(domain_lower == mining_sub_domain or domain_lower.endswith(f".{mining_sub_domain}") for mining_sub_domain in mining_sub_domains_data):
            logging.warning(f"Mining subdomain detected: {domain_lower}")
            return False, f"Mining subdomain detected: {domain_lower}"

        # Check against abuse subdomains
        if any(domain_lower == abuse_sub_domain or domain_lower.endswith(f".{abuse_sub_domain}") for abuse_sub_domain in abuse_sub_domains_data):
            logging.warning(f"Abuse subdomain detected: {domain_lower}")
            return False, f"Abuse subdomain detected: {domain_lower}"

        # Check against phishing subdomains
        if any(domain_lower == phishing_sub_domain or domain_lower.endswith(f".{phishing_sub_domain}") for phishing_sub_domain in phishing_sub_domains_data):
            logging.warning(f"Phishing subdomain detected: {domain_lower}")
            return False, f"Phishing subdomain detected: {domain_lower}"

        # Check against malware subdomains
        if any(domain_lower == malware_sub_domain or domain_lower.endswith(f".{malware_sub_domain}") for malware_sub_domain in malware_sub_domains_data):
            logging.warning(f"Malware subdomain detected: {domain_lower}")
            return False, f"Malware subdomain detected: {domain_lower}"

        # Check against spam domains
        if any(domain_lower == spam_domain or domain_lower.endswith(f".{spam_domain}") for spam_domain in spam_domains_data):
            logging.warning(f"Spam domain detected: {domain_lower}")
            return False, f"Spam domain detected: {domain_lower}"

        # Check against mining domains
        if any(domain_lower == mining_domain or domain_lower.endswith(f".{mining_domain}") for mining_domain in mining_domains_data):
            logging.warning(f"Mining domain detected: {domain_lower}")
            return False, f"Mining domain detected: {domain_lower}"

        # Check against abuse domains
        if any(domain_lower == abuse_domain or domain_lower.endswith(f".{abuse_domain}") for abuse_domain in abuse_domains_data):
            logging.warning(f"Abuse domain detected: {domain_lower}")
            return False, f"Abuse domain detected: {domain_lower}"

        # Check against phishing domains
        if any(domain_lower == phishing_domain or domain_lower.endswith(f".{phishing_domain}") for phishing_domain in phishing_domains_data):
            logging.warning(f"Phishing domain detected: {domain_lower}")
            return False, f"Phishing domain detected: {domain_lower}"

        # Check against malware domains
        if any(domain_lower == malware_domain or domain_lower.endswith(f".{malware_domain}") for malware_domain in malware_domains_data):
            logging.warning(f"Malware domain detected: {domain_lower}")
            return False, f"Malware domain detected: {domain_lower}"

        # Check against malware mail domains
        if any(domain_lower == malware_mail_domain or domain_lower.endswith(f".{malware_mail_domain}") for malware_mail_domain in malware_domains_mail_data):
            logging.warning(f"Malware mail domain detected: {domain_lower}")
            return False, f"Malware mail domain detected: {domain_lower}"

        # Check if domain is whitelisted
        if any(domain_lower == whitelist_domain or domain_lower.endswith(f".{whitelist_domain}") for whitelist_domain in whitelist_domains_data):
            logging.info(f"Domain {domain_lower} is whitelisted")
            return True, f"Whitelisted domain: {domain_lower}"  # Whitelisted domain is safe

        # Check if domain is whitelisted in mail data
        if any(domain_lower == whitelist_mail_domain or domain_lower.endswith(f".{whitelist_mail_domain}") for whitelist_mail_domain in whitelist_domains_mail_data):
            logging.info(f"Domain {domain_lower} is whitelisted (mail domain)")
            return True, f"Whitelisted mail domain: {domain_lower}"  # Whitelisted mail domain is safe

        # Check if domain is whitelisted in subdomains
        if any(domain_lower == whitelist_sub_domain or domain_lower.endswith(f".{whitelist_sub_domain}") for whitelist_sub_domain in whitelist_sub_domains_data):
            logging.info(f"Domain {domain_lower} is whitelisted (subdomain)")
            return True, f"Whitelisted subdomain: {domain_lower}"  # Whitelisted subdomain is safe

        # Check if domain is whitelisted in mail subdomains
        if any(domain_lower == whitelist_mail_sub_domain or domain_lower.endswith(f".{whitelist_mail_sub_domain}") for whitelist_mail_sub_domain in whitelist_mail_sub_domains_data):
            logging.info(f"Domain {domain_lower} is whitelisted (mail subdomain)")
            return True, f"Whitelisted mail subdomain: {domain_lower}"  # Whitelisted mail subdomain is safe

        logging.info(f"Domain {domain_lower} is unknown")
        return True, f"Unknown domain: {domain_lower}"  # Unknown domain, but not malicious

    except Exception as ex:
        logging.error(f"Error scanning domain {domain}: {ex}")
        return False, f"Error scanning domain {domain}: {ex}"

def scan_url_general(url):
    try:
        if url in scanned_urls_general:
            logging.info(f"URL {url} has already been scanned.")
            return True, "Already scanned"  # No issue found, continue scanning

        scanned_urls_general.append(url)  # Add to the scanned list
        logging.info(f"Scanning URL: {url}")

        # Check against the URLhaus database
        for entry in urlhaus_data:
            if entry['url'] in url:
                message = (
                    f"URL {url} matches the URLhaus signatures.\n"
                    f"ID: {entry['id']}\n"
                    f"Date Added: {entry['dateadded']}\n"
                    f"URL Status: {entry['url_status']}\n"
                    f"Last Online: {entry['last_online']}\n"
                    f"Threat: {entry['threat']}\n"
                    f"Tags: {entry['tags']}\n"
                    f"URLhaus Link: {entry['urlhaus_link']}\n"
                    f"Reporter: {entry['reporter']}"
                )
                logging.warning(message)
                return False, f"Malicious URL detected: {url}"

        logging.info(f"No match found for URL: {url}")
        return True, f"URL is safe: {url}"

    except Exception as ex:
        logging.error(f"Error scanning URL {url}: {ex}")
        return False, f"Error scanning URL {url}: {ex}"

def scan_ip_address_general(ip_address):
    try:
        # Check if the IP address is local
        if is_local_ip(ip_address):
            message = f"Skipping local IP address: {ip_address}"
            logging.info(message)
            return True, "Local IP address, skipped"  # Local IP, no need to scan

        # Check if the IP address has already been scanned
        if ip_address in scanned_ipv4_addresses_general or ip_address in scanned_ipv6_addresses_general:
            message = f"IP address {ip_address} has already been scanned."
            logging.info(message)
            return True, "IP address already scanned"  # IP already scanned, no issues

        # Determine if it's an IPv4 or IPv6 address using regex
        if re.match(IPv6_pattern, ip_address):  # IPv6
            scanned_ipv6_addresses_general.append(ip_address)
            message = f"Scanning IPv6 address: {ip_address}"
            logging.info(message)

            # Check if it matches malicious signatures
            if ip_address in ipv6_addresses_signatures_data:
                logging.warning(f"Malicious IPv6 address detected: {ip_address}")
                return False, f"Malicious IPv6 address detected: {ip_address}"

            elif ip_address in ipv6_whitelist_data:
                logging.info(f"IPv6 address {ip_address} is whitelisted")
                return True, f"Whitelisted IPv6 address: {ip_address}"  # Whitelisted IP

            else:
                logging.info(f"Unknown IPv6 address detected: {ip_address}")
                return True, f"Unknown IPv6 address detected: {ip_address}"  # Unknown, but safe

        elif re.match(IPv4_pattern, ip_address):  # IPv4
            scanned_ipv4_addresses_general.append(ip_address)
            message = f"Scanning IPv4 address: {ip_address}"
            logging.info(message)

            # Check if it matches malicious signatures
            if ip_address in ipv4_addresses_signatures_data:
                logging.warning(f"Malicious IPv4 address detected: {ip_address}")
                return False, f"Malicious IPv4 address detected: {ip_address}"

            elif ip_address in ipv4_whitelist_data:
                logging.info(f"IPv4 address {ip_address} is whitelisted")
                return True, f"Whitelisted IPv4 address: {ip_address}"  # Whitelisted IP

            else:
                logging.info(f"Unknown IPv4 address detected: {ip_address}")
                return True, f"Unknown IPv4 address detected: {ip_address}"  # Unknown, but safe

    except Exception as ex:
        logging.error(f"Error scanning IP address {ip_address}: {ex}")
        return False, f"Error scanning IP address {ip_address}: {ex}"

def scan_website_content(url):
    """
    Scan website content by saving it to a specific directory and analyzing it.
    Returns a tuple of (is_malicious, threat_details, scanner_name)
    """
    try:
        logging.info(f"Scanning cleaned URL: {url}")

        # Extract the main domain (e.g., example.com)
        parsed_url = urlparse(url)
        main_domain = parsed_url.netloc

        logging.info(f"Scanning main domain: {main_domain}")

        # Create a session with headers to mimic a browser
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

        # Fetch the website content
        logging.info(f"Fetching content from: {url}")
        response = session.get(url, timeout=30)
        response.raise_for_status()

        # Generate a file name based on the URL (sanitize the URL for a valid file name)
        filename = main_domain.replace('https://', '').replace('http://', '').replace('/', '_') + '.html'
        file_path = os.path.join(website_extracted_dir, filename)

        # Save the website content to the directory
        with open(file_path, 'wb') as file:
            file.write(response.content)

        # List to hold malicious domains found
        malicious_domains = []

        try:
            # Scan the saved file using the existing scan_file_real_time function
            logging.info(f"Scanning website content from: {file_path}")
            is_malicious, threat_details, scanner_name = scan_file_real_time(file_path)

            # If the file is flagged as malicious, return immediately
            if is_malicious:
                malicious_domains.append(main_domain)

            # Check for Discord webhook (if any)
            if contains_discord_code(response.text):
                malicious_domains.append(main_domain)
                return True, "Discord webhook detected", "WebContentAnalyzer"

            # Scan for malicious URLs, domains, and IPs in the content
            result, reason = scan_code_for_links(response.text)
            if not result:
                # If malicious domains are found, append them and return the result
                malicious_domains.append(main_domain)
                return True, reason, scanner_name

            # If everything checks out, return True, indicating the site is safe
            if malicious_domains:
                # Limit to 5 malicious domains
                return True, f"Malicious domains detected: {', '.join(malicious_domains[:5])}", scanner_name

            # If no malicious domains found
            return False, "No malicious content detected.", scanner_name

        finally:
            # Clean up the saved file after scanning (if needed)
            try:
                os.remove(file_path)
            except Exception as ex:
                logging.error(f"Error removing saved file: {ex}")

    except requests.exceptions.RequestException as ex:
        logging.error(f"Error fetching website content: {ex}")
        return False, f"Error fetching content: {str(ex)}", ""
    except Exception as ex:
        logging.error(f"Error scanning website content: {ex}")
        return False, f"Error scanning content: {str(ex)}", ""

class WorkerThread(QThread):
    update_results = Signal(str)  # Signal to update results in the UI
    finished = Signal()  # Signal when the task is done

    def __init__(self, keyword, parent=None):
        super().__init__(parent)
        self.keyword = keyword

    def is_domain_reachable(self, url):
        """Check if the domain is reachable and has valid WHOIS data."""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

            # Validate if the domain is a proper domain
            if not self.is_valid_domain(domain):
                self.update_results.emit(f"[ERROR] Invalid domain: {domain}\n")
                return False

            # Check if the domain resolves to an IP (DNS resolution)
            try:
                socket.gethostbyname(domain)  # Try to resolve the domain
            except socket.gaierror:
                self.update_results.emit(f"[ERROR] Domain {domain} is unreachable (DNS resolution failed).\n")
                return False

            # Check the domain's registration status using WHOIS
            try:
                domain_info = whois.whois(domain)
                if not domain_info.status:
                    self.update_results.emit(f"[WARNING] Domain {domain} does not have valid WHOIS data or is not active.\n")
                    return False
            except Exception as e:
                self.update_results.emit(f"[ERROR] Error retrieving WHOIS information for {domain}: {e}\n")
                return False

            # Check if the domain is reachable by making an HTTP request
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    return True
                else:
                    self.update_results.emit(f"[WARNING] Domain {domain} returned status code {response.status_code}.\n")
                    return False
            except requests.exceptions.RequestException as e:
                self.update_results.emit(f"[ERROR] Domain {domain} is unreachable - HTTP error: {e}\n")
                return False

        except Exception as e:
            self.update_results.emit(f"[ERROR] Error checking domain {url}: {e}\n")
            return False

    def is_valid_domain(self, domain):
        """Check if the domain is valid."""
        # Regular expression to validate domain (basic validation)
        domain_regex = r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
        return re.match(domain_regex, domain) is not None

    def run(self):
        """Run the search and scan tasks in the background."""
        try:
            # Simulate searching for websites based on the keyword
            websites = search(self.keyword, num_results=5)  # First 5 results
            self.update_results.emit(f"Searching websites for: {self.keyword}\n")

            for url in websites:
                self.update_results.emit(f"Scanning: {url}\n")

                # Check if the domain is reachable and valid
                if not self.is_domain_reachable(url):
                    continue

                # Scan the website
                is_malicious, threat_details, scanner_name = scan_website_content(url)

                if is_malicious:
                    self.update_results.emit(f"[MALICIOUS] {url}\nDetails: {threat_details}\nScanner: {scanner_name}\n")
                else:
                    self.update_results.emit(f"[CLEAN] {url}\n")

                # Clear the lists after each URL scan
                self.clean_scan_lists()

        except Exception as e:
            self.update_results.emit(f"Error during search and scan: {e}\n")
        finally:
            self.finished.emit()  # Emit finished signal when done

    def clean_scan_lists(self):
        """Clear the scan lists."""
        global scanned_urls_general, scanned_domains_general, scanned_ipv4_addresses_general, scanned_ipv6_addresses_general
        scanned_urls_general.clear()
        scanned_domains_general.clear()
        scanned_ipv4_addresses_general.clear()
        scanned_ipv6_addresses_general.clear()
        self.update_results.emit("Scan lists cleared.\n")

class LocalSearchAntivirus(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Local Search Antivirus - Hydra Dragon")
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        # Set the window icon
        self.setWindowIcon(QIcon("assets/HydraDragonAV.png"))

        # User input for keyword
        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText("Enter a keyword to search websites")
        layout.addWidget(self.keyword_input)

        # Search & Scan button
        self.search_button = QPushButton("Search & Scan")
        self.search_button.clicked.connect(self.start_search_and_scan)
        layout.addWidget(self.search_button)

        # Text area to show results
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)

        self.setLayout(layout)

    def start_search_and_scan(self):
        """Start the search and scan process in a new thread."""
        keyword = self.keyword_input.text().strip()
        if not keyword:
            self.result_text.setText("Please enter a keyword.")
            return

        self.result_text.setText(f"Searching websites for: {keyword}\n")
        QApplication.processEvents()

        # Start worker thread to search and scan websites
        self.worker_thread = WorkerThread(keyword)
        self.worker_thread.update_results.connect(self.update_results)  # Connect the signal to update results
        self.worker_thread.finished.connect(self.on_finished)  # Connect the finished signal
        self.worker_thread.start()

    def update_results(self, result_text):
        """Update the text area with results from the worker thread."""
        self.result_text.append(result_text)
        QApplication.processEvents()

    def on_finished(self):
        """Handle the finished signal from the worker thread."""
        self.result_text.append("\nScanning completed.")
        QApplication.processEvents()

def main():
    try:
        app = QApplication(sys.argv)
        app.setStyleSheet(antivirus_style)  # Apply the style sheet
        main_gui = LocalSearchAntivirus()
        main_gui.show()
        sys.exit(app.exec())
    except Exception as ex:
        print(f"An error occurred: {ex}")

if __name__ == "__main__":
    main()
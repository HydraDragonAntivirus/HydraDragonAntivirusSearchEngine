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
import subprocess
print(f"subprocess module loaded in {time.time() - start_time:.6f} seconds")

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
import yara
print(f"yara module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from googlesearch import search
print(f"googlesearch.search module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import yara_x
print(f"yara_x module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import ipaddress
print(f"ipaddress module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import binascii
print(f"binascii module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import threading
print(f"threading module loaded in {time.time() - start_time:.6f} seconds")

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

def restart_clamd_thread():
    try:
        threading.Thread(target=restart_clamd).start()
    except Exception as ex:
        logging.error(f"Error starting clamd restart thread: {ex}")
        print(f"Error starting clamd restart thread: {ex}")

def restart_clamd():
    try:
        print("Stopping ClamAV...")
        stop_result = subprocess.run(["net", "stop", 'clamd'], capture_output=True, text=True)
        if stop_result.returncode != 0:
                logging.error("Failed to stop ClamAV.")
                print("Failed to stop ClamAV.")
            
        print("Starting ClamAV...")
        start_result = subprocess.run(["net", "start", 'clamd'], capture_output=True, text=True)
        if start_result.returncode == 0:
            logging.info("ClamAV restarted successfully.")
            print("ClamAV restarted successfully.")
            return True
        else:
            logging.error("Failed to start ClamAV.")
            print("Failed to start ClamAV.")
            return False
    except Exception as ex:
        logging.error(f"An error occurred while restarting ClamAV: {ex}")
        print(f"An error occurred while restarting ClamAV: {ex}")
        return False

general_extracted_dir = os.path.join(script_dir, "general_extracted")
website_extracted_dir = os.path.join(script_dir, "website_extracted")
website_rules_dir = os.path.join(script_dir, "website")
yara_folder_path = os.path.join(script_dir, "yara")
excluded_rules_dir = os.path.join(script_dir, "excluded")
excluded_rules_path = os.path.join(excluded_rules_dir, "excluded_rules.txt")
ipv4_addresses_path = os.path.join(website_rules_dir, "IPv4Malware.txt")
ipv4_whitelist_path = os.path.join(website_rules_dir, "IPv4Whitelist.txt")
ipv6_addresses_path = os.path.join(website_rules_dir, "IPv6Malware.txt")
ipv6_whitelist_path = os.path.join(website_rules_dir, "IPv6Whitelist.txt")
malware_domains_path = os.path.join(website_rules_dir, "MalwareDomains.txt")
malware_domains_mail_path = os.path.join(website_rules_dir, "MalwareDomainsMail.txt")
phishing_domains_path = os.path.join(website_rules_dir, "PhishingDomains.txt")
abuse_domains_path = os.path.join(website_rules_dir, "AbuseDomains.txt")
mining_domains_path = os.path.join(website_rules_dir, "MiningDomains.txt")
spam_domains_path = os.path.join(website_rules_dir, "SpamDomains.txt")
whitelist_domains_path = os.path.join(website_rules_dir, "WhiteListDomains.txt")
whitelist_domains_mail_path = os.path.join(website_rules_dir, "WhiteListDomainsMail.txt")
urlhaus_path = os.path.join(website_rules_dir, "urlhaus.txt")
antivirus_list_path = os.path.join(script_dir, "hosts", "antivirus_list.txt")
yaraxtr_yrc_path = os.path.join(yara_folder_path, "yaraxtr.yrc")
compiled_rule_path = os.path.join(yara_folder_path, "compiled_rule.yrc")
yarGen_rule_path = os.path.join(yara_folder_path, "machinelearning.yrc")
icewater_rule_path = os.path.join(yara_folder_path, "icewater.yrc")
valhalla_rule_path = os.path.join(yara_folder_path, "valhalla-rules.yrc")
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
# Scanned entities with "_general" suffix
scanned_urls_general = []
scanned_domains_general = []
scanned_ipv4_addresses_general = []
scanned_ipv6_addresses_general = []
restart_clamd_thread()

clamdscan_path = "C:\\Program Files\\ClamAV\\clamdscan.exe"
freshclam_path = "C:\\Program Files\\ClamAV\\freshclam.exe"
clamav_file_paths = ["C:\\Program Files\\ClamAV\\database\\daily.cvd", "C:\\Program Files\\ClamAV\\database\\daily.cld"]
clamav_database_directory_path = "C:\\Program Files\\ClamAV\\database"
seven_zip_path = "C:\\Program Files\\7-Zip\\7z.exe"  # Path to 7z.exe

IPv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'  # Simple IPv4 regex
IPv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'  # Simple IPv6 regex

os.makedirs(general_extracted_dir, exist_ok=True)
os.makedirs(website_extracted_dir, exist_ok=True)

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

def is_hex_data(data_content):
    """Check if the given binary data can be valid hex-encoded data."""
    try:
        # Convert binary data to hex representation and back to binary
        binascii.unhexlify(binascii.hexlify(data_content))
        return True
    except (TypeError, binascii.Error):
        return False

try:
    # Load excluded rules from text file
    with open(excluded_rules_path, "r") as excluded_file:
        excluded_rules = excluded_file.read()
        print("YARA Excluded Rules Definitions loaded!")
except Exception as e:
    print(f"Error loading excluded rules: {e}")

try:
    # Load the precompiled yarGen rules from the .yrc file
    yarGen_rule = yara.load(yarGen_rule_path)
    print("yarGen Rules Definitions loaded!")
except yara.Error as e:
    print(f"Error loading precompiled YARA rule: {e}")

try:
    # Load the precompiled icewater rules from the .yrc file
    icewater_rule = yara.load(icewater_rule_path)
    print("Icewater Rules Definitions loaded!")
except yara.Error as e:
    print(f"Error loading precompiled YARA rule: {e}")

try:
    # Load the precompiled valhalla rules from the .yrc file
    valhalla_rule = yara.load(valhalla_rule_path)
    print("Vallhalla Demo Rules Definitions loaded!")
except yara.Error as e:
    print(f"Error loading precompiled YARA rule: {e}")

try:
    # Load the precompiled rules from the .yrc file
    compiled_rule = yara.load(compiled_rule_path)
    print("YARA Rules Definitions loaded!")
except yara.Error as e:
    print(f"Error loading precompiled YARA rule: {e}")

try:
    # Load the precompiled rule from the .yrc file using yara_x
    with open(yaraxtr_yrc_path, 'rb') as yara_x_f:
        yaraxtr_rule = yara_x.Rules.deserialize_from(yara_x_f)
    print("YARA-X Rules Definitions loaded!")
except Exception as e:
    print(f"Error loading YARA-X rules: {e}")

def load_domains_data():
    global ipv4_addresses_signatures_data, ipv4_whitelist_data, ipv6_addresses_signatures_data, ipv6_whitelist_data, urlhaus_data, malware_domains_data, malware_domains_mail_data, phishing_domains_data, abuse_domains_data, mining_domains_data, spam_domains_data, whitelist_domains_data, whitelist_domains_mail_data

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

    print("All domain and ip address files loaded successfully!")

load_domains_data()

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
                return False, f"Malicious or problematic URL detected: {reason}"

        # Scan for domains (simplified regex)
        domains = set(re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', decompiled_code))
        for domain in domains:
            result, reason = scan_domain_general(domain)
            if not result:
                return False, f"Malicious or problematic domain detected: {reason}"

        # Scan for IP addresses (IPv4)
        ipv4_addresses = set(re.findall(r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', decompiled_code))
        for ip in ipv4_addresses:
            result, reason = scan_ip_address_general(ip)
            if not result:
                return False, f"Malicious or problematic IPv4 address detected: {reason}"

        # Scan for IP addresses (IPv6)
        ipv6_addresses = set(re.findall(r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}', decompiled_code))
        for ip in ipv6_addresses:
            result, reason = scan_ip_address_general(ip)
            if not result:
                return False, f"Malicious or problematic IPv6 address detected: {reason}"

        # If no issues are found
        return True, "No malicious or whitelisted URLs, domains, or IPs detected."

    except Exception as ex:
        logging.error(f"Error scanning code for links: {ex}")
        return False, f"Error scanning code for links: {ex}"

# Updated generalized scan functions to return True/False with reason for success or failure
def scan_domain_general(domain):
    try:
        if domain in scanned_domains_general:
            logging.info(f"Domain {domain} has already been scanned.")
            return True, "Already scanned"  # No issue found, continue scanning

        scanned_domains_general.append(domain)  # Add to the scanned list
        logging.info(f"Scanning domain: {domain}")

        # Check for malicious domains
        if any(domain.lower() == malicious_domain or domain.lower().endswith(f".{malicious_domain}") for malicious_domain in malware_domains_data):
            logging.warning(f"Malicious domain detected: {domain}")
            return False, f"Malicious domain detected: {domain}"

        # Check for phishing domains
        if any(domain.lower() == phishing_domain or domain.lower().endswith(f".{phishing_domain}") for phishing_domain in phishing_domains_data):
            logging.warning(f"Phishing domain detected: {domain}")
            return False, f"Phishing domain detected: {domain}"

        # Check for abuse domains
        if any(domain.lower() == abuse_domain or domain.lower().endswith(f".{abuse_domain}") for abuse_domain in abuse_domains_data):
            logging.warning(f"Abuse domain detected: {domain}")
            return False, f"Abuse domain detected: {domain}"

        # Check for mining domains
        if any(domain.lower() == mining_domain or domain.lower().endswith(f".{mining_domain}") for mining_domain in mining_domains_data):
            logging.warning(f"Mining domain detected: {domain}")
            return False, f"Mining domain detected: {domain}"

        # Check for spam domains
        if any(domain.lower() == spam_domain or domain.lower().endswith(f".{spam_domain}") for spam_domain in spam_domains_data):
            logging.warning(f"Spam domain detected: {domain}")
            return False, f"Spam domain detected: {domain}"

        # Check if domain is whitelisted
        if any(domain.lower() == whitelisted_domain or domain.lower().endswith(f".{whitelisted_domain}") for whitelisted_domain in whitelist_domains_data):
            logging.info(f"Domain {domain} is whitelisted")
            return True, f"Whitelisted domain: {domain}"  # Whitelisted domain is safe

        logging.info(f"Domain {domain} is unknown")
        return True, f"Unknown domain detected: {domain}"  # Unknown domain, but not malicious

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
        else:
            logging.debug(f"Invalid IP address format detected: {ip_address}")
            return True, f"Invalid IP address format: {ip_address}"

    except Exception as ex:
        logging.error(f"Error scanning IP address {ip_address}: {ex}")
        return False, f"Error scanning IP address {ip_address}: {ex}"

# Function to extract all files from an archive using 7z.exe (no focus on extension)
def extract_all_files_with_7z(file_path):
    try:
        counter = 1
        base_output_dir = os.path.join(general_extracted_dir, os.path.splitext(os.path.basename(file_path))[0])

        # Ensure output directory is unique
        while os.path.exists(f"{base_output_dir}_{counter}"):
            counter += 1

        output_dir = f"{base_output_dir}_{counter}"
        os.makedirs(output_dir, exist_ok=True)

        logging.info(f"Attempting to extract file {file_path} into {output_dir}...")

        # Run the 7z extraction command
        command = [seven_zip_path, "x", file_path, f"-o{output_dir}", "-y", "-snl", "-spe"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            logging.error(f"7z extraction failed with return code {result.returncode}: {result.stderr}")
            return []

        logging.info(f"7z extraction successful for {file_path}.")

        # Gather all files in the output directory after extraction
        extracted_files = []
        for root, _, files in os.walk(output_dir):
            for name in files:
                extracted_files.append(os.path.join(root, name))

        if not extracted_files:
            logging.warning(f"No files were extracted from {file_path}.")
        else:
            logging.info(f"Extracted {len(extracted_files)} files from {file_path}.")

        return extracted_files

    except Exception as ex:
        logging.error(f"Error during extraction with 7z: {ex}")
        return []

# Hex data validation function
def is_hex_data(data_content):
    """Check if the given binary data can be valid hex-encoded data."""
    try:
        # Convert binary data to hex representation and back to binary
        binascii.unhexlify(binascii.hexlify(data_content))
        return True
    except (TypeError, binascii.Error):
        return False

# Function to read file content
def read_file_content(file_path):
    """Reads the content of the given file."""
    try:
        with open(file_path, 'rb') as file:
            return file.read()
    except Exception as ex:
        logging.error(f"Error reading file {file_path}: {ex}")
        return None

def scan_file_with_clamd(file_path):
    """Scan file using clamd."""
    try:
        file_path = os.path.abspath(file_path)  # Get absolute path
        result = subprocess.run([clamdscan_path, file_path], capture_output=True, text=True)
        clamd_output = result.stdout
        print(f"Clamdscan output: {clamd_output}")

        if "ERROR" in clamd_output:
            print(f"Clamdscan reported an error: {clamd_output}")
            return "Clean"
        elif "FOUND" in clamd_output:
            match = re.search(r": (.+) FOUND", clamd_output)
            if match:
                virus_name = match.group(1).strip()
                return virus_name
        elif "OK" in clamd_output or "Infected files: 0" in clamd_output:
            return "Clean"
        else:
            print(f"Unexpected clamdscan output: {clamd_output}")
            return "Clean"
    except Exception as ex:
        logging.error(f"Error scanning file {file_path}: {ex}")
        print(f"Error scanning file {file_path}: {ex}")
        return "Clean"

# Updated scan_file_real_time function to handle hex data and 7z extraction
def scan_file_real_time(file_path):
    """Scan file in real-time using multiple engines and extract files with 7z or handle hex data."""
    logging.info(f"Started scanning file: {file_path}")

    try:
        # Read file content
        data_content = read_file_content(file_path)
        if not data_content:
            logging.error(f"Unable to read content of the file: {file_path}")
            return False, "Error reading file", ""

        # If hex data is detected in the content, attempt extraction with 7z
        if is_hex_data(data_content):
            logging.info(f"Hex data detected in {file_path}, attempting to extract files...")

            # Extract files with 7z (general extraction, no extension focus)
            extracted_files = extract_all_files_with_7z(file_path)
                
            if not extracted_files:
                logging.warning(f"No files extracted from the archive: {file_path}")
            else:
                for extracted_file in extracted_files:
                    logging.info(f"Scanning extracted file: {extracted_file}")
                    scan_file_real_time(extracted_file)  # Recursive scan for extracted files

        # Continue with scanning if hex data is not detected or after extracting files
        # Scan with ClamAV
        try:
            result = scan_file_with_clamd(file_path)
            if result not in ("Clean", ""):
                logging.warning(f"Infected file detected (ClamAV): {file_path} - Virus: {result}")
                return True, result, "ClamAV"
            logging.info(f"No malware detected by ClamAV in file: {file_path}")
        except Exception as ex:
            logging.error(f"An error occurred while scanning file with ClamAV: {file_path}. Error: {ex}")

        # Scan with YARA
        try:
            yara_result = scan_yara(file_path)
            if yara_result is not None and yara_result not in ("Clean", ""):
                logging.warning(f"Infected file detected (YARA): {file_path} - Virus: {yara_result}")
                return True, yara_result, "YARA"
            logging.info(f"Scanned file with YARA: {file_path} - No viruses detected")
        except Exception as ex:
            logging.error(f"An error occurred while scanning file with YARA: {file_path}. Error: {ex}")

    except Exception as ex:
        logging.error(f"An error occurred while scanning file: {file_path}. Error: {ex}")

    return False, "Clean", ""  # Default to clean if no malware found

def scan_yara(file_path):
    matched_rules = []

    try:
        if not os.path.exists(file_path):
            logging.error(f"File not found during YARA scan: {file_path}")
            return None

        with open(file_path, 'rb') as yara_file:
            data_content = yara_file.read()

            # Check matches for compiled_rule
            if compiled_rule:
                matches = compiled_rule.match(data=data_content)
                if matches:
                    for match in matches:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded from compiled_rule.")
            else:
                logging.warning("compiled_rule is not defined.")

            # Check matches for yarGen_rule
            if yarGen_rule:
                matches = yarGen_rule.match(data=data_content)
                if matches:
                    for match in matches:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded from yarGen_rule.")
            else:
                logging.warning("yarGen_rule is not defined.")

            # Check matches for icewater_rule
            if icewater_rule:
                matches = icewater_rule.match(data=data_content)
                if matches:
                    for match in matches:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded from icewater_rule.")
            else:
                logging.warning("icewater_rule is not defined.")

            # Check matches for valhalla_rule
            if valhalla_rule:
                matches = valhalla_rule.match(data=data_content)
                if matches:
                    for match in matches:
                        if match.rule not in excluded_rules:
                            matched_rules.append(match.rule)
                        else:
                            logging.info(f"Rule {match.rule} is excluded from valhalla_rule.")
            else:
                logging.warning("valhalla_rule is not defined.")

            # Check matches for yaraxtr_rule (loaded with yara_x)
            if yaraxtr_rule:
                scanner = yara_x.Scanner(yaraxtr_rule)
                results = scanner.scan(data=data_content)
                if results.matching_rules:
                    for rule in results.matching_rules:
                        if hasattr(rule, 'identifier') and rule.identifier not in excluded_rules:
                            matched_rules.append(rule.identifier)
                        else:
                            logging.info(f"Rule {rule.identifier} is excluded from yaraxtr_rule.")
            else:
                logging.warning("yaraxtr_rule is not defined.")

        # Return matched rules as the yara_result if not empty, otherwise return None
        return matched_rules if matched_rules else None

    except Exception as ex:
        logging.error(f"An error occurred during YARA scan: {ex}")
        return None

def scan_website_content(url):
    """
    Scan website content by saving it to a specific directory.
    Returns a tuple of (is_malicious, threat_details, scanner_name)
    """
    try:
        logging.info(f"Scanning cleaned URL: {url}")

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
        filename = url.replace('https://', '').replace('http://', '').replace('/', '_') + '.html'
        file_path = os.path.join(website_extracted_dir, filename)

        # Save the website content to the directory
        with open(file_path, 'wb') as file:
            file.write(response.content)

        try:
            # Scan the saved file using the existing scan_file_real_time function
            logging.info(f"Scanning website content from: {file_path}")
            is_malicious, threat_details, scanner_name = scan_file_real_time(file_path)

            # Check for Discord webhook
            if contains_discord_code(response.text):
                is_malicious = True
                threat_details = "Discord webhook detected"
                scanner_name = "WebContentAnalyzer"

            # Scan for malicious URLs, domains, and IPs in the content
            result, reason = scan_code_for_links(response.text)
            if not result:
                return False, reason, scanner_name  # Return the reason if any issue is found

            # If everything checks out, return the result from scan_file_real_time
            return is_malicious, threat_details, scanner_name

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
import os
import sys
import logging
import io
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

# Redirect stdout to console log
sys.stdout = open(console_log_file, "w", encoding="utf-8", errors="replace")

# Redirect stderr to console log
sys.stderr = open(console_log_file, "w", encoding="utf-8", errors="replace")

# Redirect stdin to a log file
sys.stdin = open(stdin_log_file, "w+", encoding="utf-8", errors="replace")

# Logging for application initialization
logging.info("Application started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# Record the start time for total duration
total_start_time = time.time()

start_time = time.time()
import yara
print(f"yara module loaded in {time.time() - start_time:.6f} seconds")

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
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QMessageBox, QStackedWidget
print(f"PySide6.QtWidgets modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtCore import QObject, QThread, Signal
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
website_rules_dir = os.path.join(script_dir, "website")
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

# Scan for domains, URLs, and IPs in the decompiled code
def scan_code_for_links(decompiled_code):
    """
    Scan the decompiled code for domains, URLs, and IP addresses, removing duplicates.
    """
    # Scan for URLs
    urls = set(re.findall(r'https?://[^\s/$.?#].[^\s]*', decompiled_code))
    for url in urls:
        scan_url_general(url)

    # Scan for domains (simplified regex)
    domains = set(re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', decompiled_code))
    for domain in domains:
        scan_domain_general(domain)

    # Scan for IP addresses (IPv4)
    ipv4_addresses = set(re.findall(r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', decompiled_code))
    for ip in ipv4_addresses:
        scan_ip_address_general(ip)

    # Scan for IP addresses (IPv6)
    ipv6_addresses = set(re.findall(r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}', decompiled_code))
    for ip in ipv6_addresses:
        scan_ip_address_general(ip)

# Generalized scan for domains
def scan_domain_general(domain):
    try:
        if domain in scanned_domains_general:
            logging.info(f"Domain {domain} has already been scanned.")
            return

        scanned_domains_general.append(domain)  # Add to the scanned list
        logging.info(f"Scanning domain: {domain}")

        # Check for malicious domains
        if any(domain.lower() == malicious_domain or domain.lower().endswith(f".{malicious_domain}") for malicious_domain in malware_domains_data):
            logging.warning(f"Malicious domain detected: {domain}")
            return

        # Check if domain is whitelisted
        if any(domain.lower() == whitelisted_domain or domain.lower().endswith(f".{whitelisted_domain}") for whitelisted_domain in whitelist_domains_data):
            logging.info(f"Domain {domain} is whitelisted")
            return

        logging.info(f"Domain {domain} is not malicious or whitelisted")
        print(f"Domain {domain} is not malicious or whitelisted")

    except Exception as ex:
        logging.error(f"Error scanning domain {domain}: {ex}")
        print(f"Error scanning domain {domain}: {ex}")

# Generalized scan for URLs
def scan_url_general(url):
    try:
        if url in scanned_urls_general:
            logging.info(f"URL {url} has already been scanned.")
            return

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
                print(message)
                return

        logging.info(f"No match found for URL: {url}")
        print(f"No match found for URL: {url}")

    except Exception as ex:
        logging.error(f"Error scanning URL {url}: {ex}")
        print(f"Error scanning URL {url}: {ex}")

# Generalized scan for IP addresses
def scan_ip_address_general(ip_address):
    try:
        # Check if the IP address is local
        if is_local_ip(ip_address):
            message = f"Skipping local IP address: {ip_address}"
            logging.info(message)
            print(message)
            return

        # Check if the IP address has already been scanned
        if ip_address in scanned_ipv4_addresses_general or ip_address in scanned_ipv6_addresses_general:
            message = f"IP address {ip_address} has already been scanned."
            logging.info(message)
            print(message)
            return

        # Determine if it's an IPv4 or IPv6 address using regex
        if re.match(IPv6_pattern, ip_address):  # IPv6
            scanned_ipv6_addresses_general.append(ip_address)
            message = f"Scanning IPv6 address: {ip_address}"
            logging.info(message)
            print(message)

            # Check if it matches malicious signatures
            if ip_address in ipv6_addresses_signatures_data:
                logging.warning(f"Malicious IPv6 address detected: {ip_address}")

            elif ip_address in ipv6_whitelist_data:
                logging.info(f"IPv6 address {ip_address} is whitelisted")
                return
            else:
                logging.info(f"Unknown IPv6 address detected: {ip_address}")
                print(f"Unknown IPv6 address detected: {ip_address}")

        elif re.match(IPv4_pattern, ip_address):  # IPv4
            scanned_ipv4_addresses_general.append(ip_address)
            message = f"Scanning IPv4 address: {ip_address}"
            logging.info(message)
            print(message)

            # Check if it matches malicious signatures
            if ip_address in ipv4_addresses_signatures_data:
                logging.warning(f"Malicious IPv4 address detected: {ip_address}")

            elif ip_address in ipv4_whitelist_data:
                logging.info(f"IPv4 address {ip_address} is whitelisted")
                return
            else:
                logging.info(f"Unknown IPv4 address detected: {ip_address}")
                print(f"Unknown IPv4 address detected: {ip_address}")
        else:
            logging.debug(f"Invalid IP address format detected: {ip_address}")
            print(f"Invalid IP address format detected: {ip_address}")

    except Exception as ex:
        logging.error(f"Error scanning IP address {ip_address}: {ex}")
        print(f"Error scanning IP address {ip_address}: {ex}")

# Function to check if the IP is a local IP address
def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

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

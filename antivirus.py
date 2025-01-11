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
            notify_user_for_malicious_source_code(domain, 'HEUR:Win32.SourceCode.Malicious.Domain')
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

                # Notify the user about the malicious URL
                notify_user_for_malicious_source_code(url, 'HEUR:Win32.SourceCode.URLhaus.Match')
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
                notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.SourceCode.Malware.IPv6')

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
                notify_user_for_malicious_source_code(ip_address, 'HEUR:Win32.SourceCode.Malware.IPv4')

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

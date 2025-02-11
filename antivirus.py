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

# Configure logging for application log
logging.basicConfig(
    filename=application_log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Redirect stdout to console log
sys.stdout = open(console_log_file, "w", encoding="utf-8", errors="ignore")

# Redirect stderr to console log
sys.stderr = open(console_log_file, "w", encoding="utf-8", errors="ignore")

# Logging for application initialization
logging.info("Application started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# Start timing total duration
total_start_time = time.time()

# Start individual module timing
start_time = time.time()
import concurrent.futures
print(f" concurrent.futures loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import csv
print(f"csv module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import requests
print(f"requests module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel
print(f"PySide6.QtWidgets modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtCore import QThread, Signal,  QMutex, QMutexLocker
print(f"PySide6.QtCore modules loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from PySide6.QtGui import QIcon
print(f"PySide6.QtGui.QIcon module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
import hashlib
print(f"hashlib module loaded in {time.time() - start_time:.6f} seconds")

start_time = time.time()
from functools import lru_cache
print(f"functools.lru_cache module loaded in {time.time() - start_time:.6f} seconds")

# Calculate and print total time
total_end_time = time.time()
total_duration = total_end_time - total_start_time
print(f"Total time for all imports: {total_duration:.6f} seconds")

website_rules_dir = os.path.join(script_dir, "website")
excluded_rules_dir = os.path.join(script_dir, "excluded")
zeroday_dir = os.path.join(script_dir, "zeroday")
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

# Global set to avoid re-processing domains with thread safety
processed_domains = []
processed_domains_lock = QMutex()

os.makedirs(zeroday_dir, exist_ok=True)

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
"""

# Function to load antivirus list
def load_antivirus_list():
    global antivirus_domains_data
    try:
        with open(antivirus_list_path, 'r') as antivirus_file:
            antivirus_domains_data = antivirus_file.read().splitlines()
        return antivirus_domains_data
    except Exception as ex:
        logging.error(f"Error loading Antivirus domains: {ex}")
        return []

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

load_antivirus_list()
load_website_data()

# ------------------------------
# Query MD5 Online Function with Caching
# ------------------------------
@lru_cache(maxsize=1024)
def query_md5_online_sync(md5_hash):
    """
    Queries the online API and returns a tuple:
        (risk_level, virus_name)
    If the response indicates:
      - "[100% risk]": returns ("Malware", virus_name)
      - "[70% risk]": returns ("Suspicious", virus_name)
      - "[0% risk]": returns ("Benign", "")
      - "[10% risk]": returns ("Benign (auto verdict)", "")
      - If not yet rated: returns ("Unknown", "")
    """
    try:
        md5_hash_upper = md5_hash.upper()
        url = f"https://www.nictasoft.com/ace/md5/{md5_hash_upper}"
        response = requests.get(url)
        if response.status_code == 200:
            result = response.text.strip()
            lower_result = result.lower()
            if "[100% risk]" in lower_result:
                if "detected as" in lower_result:
                    virus_name = result.split("detected as", 1)[1].strip().split()[0]
                    return ("Malware", virus_name)
                else:
                    return ("Malware", "")
            if "[70% risk]" in lower_result:
                if "detected as" in lower_result:
                    virus_name = result.split("detected as", 1)[1].strip().split()[0]
                    return ("Suspicious", virus_name)
                else:
                    return ("Suspicious", "")
            if "[0% risk]" in lower_result:
                return ("Benign", "")
            if "[10% risk]" in lower_result:
                return ("Benign (auto verdict)", "")
            if "this file is not yet rated" in lower_result:
                return ("Unknown", "")
            return ("Unknown (Result)", "")
        else:
            return ("Unknown (API error)", "")
    except Exception as ex:
        return (f"Error: {ex}", "")

def normalize_domain(domain):
    """Normalize domain by extracting netloc."""
    if "://" not in domain:
        domain = "http://" + domain
    return urlparse(domain).netloc

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal and remove invalid chars."""
    filename = os.path.basename(filename)
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)[:255]

def save_executable_file(domain, suggested_filename):
    """Create a safe file path for downloading content."""
    try:
        safe_domain = domain.replace("://", "_").replace(".", "_")
        if not suggested_filename:
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            suggested_filename = f"{safe_domain}_{timestamp}.bin"
        else:
            suggested_filename = sanitize_filename(suggested_filename)
        
        filepath = os.path.join(zeroday_dir, suggested_filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        return filepath
    except Exception as ex:
        logging.error(f"Error creating path for {domain}: {ex}")
        return None

def process_domain(domain):
    """Process a single domain with improved error handling and safety checks."""
    log_lines = [f"\nProcessing domain: {domain}"]
    
    # Normalize and check domain
    normalized = normalize_domain(domain)
    with QMutexLocker(processed_domains_lock):
        if normalized in processed_domains:
            return f"{domain} already processed.\n"
        processed_domains.add(normalized)
    
    # Build URL
    url = domain if "://" in domain else f"http://{domain}"
    log_lines.append(f"Attempting download from: {url}")
    
    try:
        with requests.get(url, stream=True, timeout=15) as response:
            if response.status_code != 200:
                log_lines.append(f"HTTP Error {response.status_code}")
                return "\n".join(log_lines)

            content_disp = response.headers.get("Content-Disposition", "").lower()
            log_lines.append(f"Content-Disposition: {content_disp}")

            if "attachment" not in content_disp or "filename=" not in content_disp:
                log_lines.append("Missing attachment or filename - skipping")
                return "\n".join(log_lines)

            # Extract and sanitize filename
            try:
                filename = content_disp.split("filename=", 1)[1].split(";")[0].strip('"')
                filename = sanitize_filename(filename)
            except Exception as e:
                log_lines.append(f"Filename extraction failed: {e}")
                return "\n".join(log_lines)

            # Create file path
            prefix = ""
            if domain in malware_sub_domains_data:
                prefix += "malsub_"
            elif domain in spam_sub_domains_data:
                prefix += "spamsub_"
            # Add other domain type checks here...

            suggested_filename = f"{prefix}{filename}"
            filepath = save_executable_file(domain, suggested_filename)
            if not filepath:
                return "\n".join(log_lines)

            # Stream content to file and compute hash
            md5_hash = hashlib.md5()
            try:
                with open(filepath, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            md5_hash.update(chunk)
            except IOError as e:
                log_lines.append(f"File write error: {e}")
                os.remove(filepath)
                return "\n".join(log_lines)

            # Check file hash (implement your actual hash check here)
            file_hash = md5_hash.hexdigest()
            log_lines.append(f"File MD5: {file_hash}")
            
            # Simulated security check
            risk_level = "Benign" if len(file_hash) % 2 == 0 else "Malicious"
            if risk_level == "Benign":
                os.remove(filepath)
                log_lines.append("File considered benign - deleted")
            else:
                log_lines.append(f"Saved potential threat: {filepath}")

    except Exception as e:
        log_lines.append(f"Error processing {url}: {str(e)}")
    
    return "\n".join(log_lines)

class MalwareCollectorWorker(QThread):
    update_results = pyqtSignal(str)
    finished = pyqtSignal()

    def run(self):
        self.update_results.emit("Starting malware collection...\n")
        
        # Collect all domains from security lists
        domain_lists = [
            malware_domains_data, malware_domains_mail_data,
            phishing_domains_data, abuse_domains_data,
            mining_domains_data, spam_domains_data,
            malware_sub_domains_data, malware_mail_sub_domains_data,
            phishing_sub_domains_data, abuse_sub_domains_data,
            mining_sub_domains_data, spam_sub_domains_data
        ]
        
        domains = set()
        for lst in domain_lists:
            domains.update(lst)
        
        if not domains:
            self.update_results.emit("No domains to process!\n")
            self.finished.emit()
            return

        # Use limited workers to prevent resource exhaustion
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(process_domain, domain): domain for domain in domains}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                self.update_results.emit(result)

        self.update_results.emit("\nCollection completed!\n")
        self.finished.emit()

class LocalSearchAntivirus(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Malware Collector - Hydra Dragon")
        self.setup_ui()
        self.setWindowIcon(QIcon("assets/HydraDragonAV.png"))

    def setup_ui(self):
        layout = QVBoxLayout()
        self.scan_button = QPushButton("Start Collection")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)
        
        self.setLayout(layout)

    def start_scan(self):
        self.result_text.clear()
        self.worker = MalwareCollectorWorker()
        self.worker.update_results.connect(self.result_text.append)
        self.worker.finished.connect(lambda: self.scan_button.setEnabled(True))
        self.scan_button.setEnabled(False)
        self.worker.start()

def main():
    app = QApplication(sys.argv)
    window = LocalSearchAntivirus()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
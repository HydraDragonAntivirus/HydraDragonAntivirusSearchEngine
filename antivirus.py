import os
import sys
import logging
from datetime import datetime
import time
import threading
import csv
import requests
import hashlib
from functools import lru_cache

from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel
from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot
from PySide6.QtGui import QIcon

# ---------------------------------------------------------
# Setup Logging and Directories
# ---------------------------------------------------------
script_dir = os.getcwd()
log_directory = os.path.join(script_dir, "log")
os.makedirs(log_directory, exist_ok=True)

console_log_file = os.path.join(log_directory, "antivirusconsole.log")
application_log_file = os.path.join(log_directory, "antivirus.log")

logging.basicConfig(
    filename=application_log_file,
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Redirect stdout and stderr to log files
sys.stdout = open(console_log_file, "w", encoding="utf-8", errors="ignore")
sys.stderr = open(console_log_file, "w", encoding="utf-8", errors="ignore")

logging.info("Application started at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# ---------------------------------------------------------
# Define File Paths
# ---------------------------------------------------------
website_rules_dir = os.path.join(script_dir, "website")
excluded_rules_dir = os.path.join(script_dir, "excluded")
zeroday_dir = os.path.join(script_dir, "zeroday")
os.makedirs(zeroday_dir, exist_ok=True)

antivirus_list_path = os.path.join(script_dir, "hosts", "antivirus_list.txt")
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
malware_sub_domains_path = os.path.join(website_rules_dir, "MalwareSubDomains.txt")
malware_mail_sub_domains_path = os.path.join(website_rules_dir, "MalwareSubDomainsMail.txt")
phishing_sub_domains_path = os.path.join(website_rules_dir, "PhishingSubDomains.txt")
abuse_sub_domains_path = os.path.join(website_rules_dir, "AbuseSubDomains.txt")
mining_sub_domains_path = os.path.join(website_rules_dir, "MiningSubDomains.txt")
spam_sub_domains_path = os.path.join(website_rules_dir, "SpamSubDomains.txt")
whitelist_sub_domains_path = os.path.join(website_rules_dir, "WhiteListSubDomains.txt")
whitelist_mail_sub_domains_path = os.path.join(website_rules_dir, "WhiteListSubDomainsMail.txt")
urlhaus_path = os.path.join(website_rules_dir, "urlhaus.txt")
excluded_rules_path = os.path.join(excluded_rules_dir, "excluded_rules.txt")

# ---------------------------------------------------------
# Global Data Variables (lists)
# ---------------------------------------------------------
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

# ---------------------------------------------------------
# GUI Style
# ---------------------------------------------------------
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
    padding: 4px 10px;
    border-radius: 8px;
    min-width: 250px;
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

# ---------------------------------------------------------
# Thread-local Session for HTTP Requests
# ---------------------------------------------------------
_thread_local = threading.local()
def get_session():
    if not hasattr(_thread_local, "session"):
        _thread_local.session = requests.Session()
        _thread_local.session.headers.update({"User-Agent": "ZeroDayMalwareCollector/1.0"})
    return _thread_local.session

# ---------------------------------------------------------
# Data Loading Functions
# ---------------------------------------------------------
def load_antivirus_list():
    global antivirus_domains_data
    try:
        with open(antivirus_list_path, 'r') as f:
            antivirus_domains_data = f.read().splitlines()
        logging.info("Antivirus list loaded successfully.")
    except Exception as ex:
        logging.error(f"Error loading antivirus list: {ex}")
    return antivirus_domains_data

def load_website_data():
    global ipv4_addresses_signatures_data, ipv4_whitelist_data, ipv6_addresses_signatures_data, ipv6_whitelist_data
    global urlhaus_data, malware_domains_data, malware_domains_mail_data, phishing_domains_data, abuse_domains_data
    global mining_domains_data, spam_domains_data, whitelist_domains_data, whitelist_domains_mail_data
    global malware_sub_domains_data, malware_mail_sub_domains_data, phishing_sub_domains_data, abuse_sub_domains_data
    global mining_sub_domains_data, spam_sub_domains_data, whitelist_sub_domains_data, whitelist_mail_sub_domains_data

    try:
        with open(ipv4_addresses_path, 'r') as f:
            ipv4_addresses_signatures_data = f.read().splitlines()
        logging.info("IPv4 Addresses loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading IPv4 Addresses: {ex}")

    try:
        with open(ipv4_whitelist_path, 'r') as f:
            ipv4_whitelist_data = f.read().splitlines()
        logging.info("IPv4 Whitelist loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading IPv4 Whitelist: {ex}")

    try:
        with open(ipv6_addresses_path, 'r') as f:
            ipv6_addresses_signatures_data = f.read().splitlines()
        logging.info("IPv6 Addresses loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading IPv6 Addresses: {ex}")

    try:
        with open(ipv6_whitelist_path, 'r') as f:
            ipv6_whitelist_data = f.read().splitlines()
        logging.info("IPv6 Whitelist loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading IPv6 Whitelist: {ex}")
        ipv6_whitelist_data = []

    try:
        urlhaus_data = []
        with open(urlhaus_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                urlhaus_data.append(row)
        logging.info("URLhaus data loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading URLhaus data: {ex}")

    # Load domain files
    try:
        with open(malware_domains_path, 'r') as f:
            malware_domains_data = f.read().splitlines()
        logging.info("Malware domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Malware domains: {ex}")
        malware_domains_data = []
    try:
        with open(malware_domains_mail_path, 'r') as f:
            malware_domains_mail_data = f.read().splitlines()
        logging.info("Malware email domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Malware email domains: {ex}")
        malware_domains_mail_data = []
    try:
        with open(phishing_domains_path, 'r') as f:
            phishing_domains_data = f.read().splitlines()
        logging.info("Phishing domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Phishing domains: {ex}")
        phishing_domains_data = []
    try:
        with open(abuse_domains_path, 'r') as f:
            abuse_domains_data = f.read().splitlines()
        logging.info("Abuse domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Abuse domains: {ex}")
        abuse_domains_data = []
    try:
        with open(mining_domains_path, 'r') as f:
            mining_domains_data = f.read().splitlines()
        logging.info("Mining domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Mining domains: {ex}")
        mining_domains_data = []
    try:
        with open(spam_domains_path, 'r') as f:
            spam_domains_data = f.read().splitlines()
        logging.info("Spam domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Spam domains: {ex}")
        spam_domains_data = []
    try:
        with open(whitelist_domains_path, 'r') as f:
            whitelist_domains_data = f.read().splitlines()
        logging.info("Whitelist domains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Whitelist domains: {ex}")
        whitelist_domains_data = []

    # Load subdomain files and later convert them to sets
    try:
        with open(malware_sub_domains_path, 'r') as f:
            malware_sub_domains_data = f.read().splitlines()
        logging.info("Malware subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Malware subdomains: {ex}")
        malware_sub_domains_data = []
    try:
        with open(malware_mail_sub_domains_path, 'r') as f:
            malware_mail_sub_domains_data = f.read().splitlines()
        logging.info("Malware mail subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Malware mail subdomains: {ex}")
        malware_mail_sub_domains_data = []
    try:
        with open(phishing_sub_domains_path, 'r') as f:
            phishing_sub_domains_data = f.read().splitlines()
        logging.info("Phishing subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Phishing subdomains: {ex}")
        phishing_sub_domains_data = []
    try:
        with open(abuse_sub_domains_path, 'r') as f:
            abuse_sub_domains_data = f.read().splitlines()
        logging.info("Abuse subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Abuse subdomains: {ex}")
        abuse_sub_domains_data = []
    try:
        with open(mining_sub_domains_path, 'r') as f:
            mining_sub_domains_data = f.read().splitlines()
        logging.info("Mining subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Mining subdomains: {ex}")
        mining_sub_domains_data = []
    try:
        with open(spam_sub_domains_path, 'r') as f:
            spam_sub_domains_data = f.read().splitlines()
        logging.info("Spam subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Spam subdomains: {ex}")
        spam_sub_domains_data = []
    try:
        with open(whitelist_sub_domains_path, 'r') as f:
            whitelist_sub_domains_data = f.read().splitlines()
        logging.info("Whitelist subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Whitelist subdomains: {ex}")
        whitelist_sub_domains_data = []
    try:
        with open(whitelist_mail_sub_domains_path, 'r') as f:
            whitelist_mail_sub_domains_data = f.read().splitlines()
        logging.info("Whitelist mail subdomains loaded successfully!")
    except Exception as ex:
        logging.error(f"Error loading Whitelist mail subdomains: {ex}")
        whitelist_mail_sub_domains_data = []

    logging.info("All domain and IP address files loaded successfully!")
    
    # Convert subdomain lists to sets for faster membership tests
    malware_sub_domains_data = set(malware_sub_domains_data)
    malware_mail_sub_domains_data = set(malware_mail_sub_domains_data)
    phishing_sub_domains_data = set(phishing_sub_domains_data)
    abuse_sub_domains_data = set(abuse_sub_domains_data)
    mining_sub_domains_data = set(mining_sub_domains_data)
    spam_sub_domains_data = set(spam_sub_domains_data)
    whitelist_sub_domains_data = set(whitelist_sub_domains_data)
    whitelist_mail_sub_domains_data = set(whitelist_mail_sub_domains_data)

load_antivirus_list()
load_website_data()

# ---------------------------------------------------------
# Global processed domains and lock for thread safety
# ---------------------------------------------------------
processed_domains = set()
processed_domains_lock = threading.Lock()

# ---------------------------------------------------------
# Query MD5 Online with Caching
# ---------------------------------------------------------
@lru_cache(maxsize=1024)
def query_md5_online_sync(md5_hash):
    try:
        md5_hash_upper = md5_hash.upper()
        url = f"https://www.nictasoft.com/ace/md5/{md5_hash_upper}"
        session = get_session()
        response = session.get(url, timeout=10)
        if response.status_code == 200:
            result = response.text.strip()
            lower_result = result.lower()
            if "[100% risk]" in lower_result:
                if "detected as" in lower_result:
                    virus_name = result.split("detected as", 1)[1].strip().split()[0]
                    return ("Malware", virus_name)
                return ("Malware", "")
            if "[70% risk]" in lower_result:
                if "detected as" in lower_result:
                    virus_name = result.split("detected as", 1)[1].strip().split()[0]
                    return ("Suspicious", virus_name)
                return ("Suspicious", "")
            if "[0% risk]" in lower_result:
                return ("Benign", "")
            if "[10% risk]" in lower_result:
                return ("Benign (auto verdict)", "")
            if "this file is not yet rated" in lower_result:
                return ("Unknown", "")
            return ("Unknown (Result)", "")
        return ("Unknown (API error)", "")
    except Exception as ex:
        return (f"Error: {ex}", "")

# ---------------------------------------------------------
# Save File Function
# ---------------------------------------------------------
def save_executable_file(domain, content, suggested_filename=None):
    try:
        if not suggested_filename:
            safe_domain = domain.replace("://", "_").replace(".", "_")
            suggested_filename = f"{safe_domain}_{datetime.now().strftime('%Y%m%d%H%M%S')}.bin"
        filepath = os.path.join(zeroday_dir, suggested_filename)
        with open(filepath, "wb") as f:
            f.write(content)
        logging.info(f"Saved file from {domain} as {filepath}")
        return filepath
    except Exception as ex:
        logging.error(f"Error saving file from {domain}: {ex}")
        return None

# ---------------------------------------------------------
# Process a Single Domain (runs in worker threads)
# ---------------------------------------------------------
def process_domain(domain):
    logging.info(f"Processing domain: {domain}")
    with processed_domains_lock:
        if domain in processed_domains:
            logging.info(f"{domain} already processed.")
            return f"{domain} already processed."
        processed_domains.add(domain)
    
    url = domain if "://" in domain else "http://" + domain
    logging.info(f"Attempting to download file from: {url}")
    try:
        session = get_session()
        response = session.get(url, stream=True, timeout=10)
        if response.status_code == 200:
            content_disp = response.headers.get("Content-Disposition", "")
            logging.info(f"Response Content-Disposition: {content_disp}")
            if "attachment" not in content_disp.lower() or "filename=" not in content_disp.lower():
                logging.info("No file download requested; skipping domain.")
                return "No file download requested; skipping domain."
            content = b"".join(chunk for chunk in response.iter_content(chunk_size=8192) if chunk)
            if content:
                md5_hash = hashlib.md5(content).hexdigest()
                risk_level, virus_name = query_md5_online_sync(md5_hash)
                logging.info(f"MD5: {md5_hash} | Query result: {risk_level} {virus_name}")
                # Do not collect clean files.
                if risk_level.startswith("Benign") or risk_level == "Benign (auto verdict)":
                    logging.info("File is considered clean; skipping collection.")
                    return "File is considered clean; skipping collection."
                else:
                    # Build a prefix using the source .txt dosya adlarını (liste adlarını) ekleyerek.
                    prefix = ""
                    if domain in malware_domains_data:
                        prefix += "MalwareDomains.txt_"
                    if domain in malware_domains_mail_data:
                        prefix += "MalwareDomainsMail.txt_"
                    if domain in phishing_domains_data:
                        prefix += "PhishingDomains.txt_"
                    if domain in abuse_domains_data:
                        prefix += "AbuseDomains.txt_"
                    if domain in mining_domains_data:
                        prefix += "MiningDomains.txt_"
                    if domain in spam_domains_data:
                        prefix += "SpamDomains.txt_"
                    if domain in malware_sub_domains_data:
                        prefix += "MalwareSubDomains.txt_"
                    if domain in malware_mail_sub_domains_data:
                        prefix += "MalwareSubDomainsMail.txt_"
                    if domain in phishing_sub_domains_data:
                        prefix += "PhishingSubDomains.txt_"
                    if domain in abuse_sub_domains_data:
                        prefix += "AbuseSubDomains.txt_"
                    if domain in mining_sub_domains_data:
                        prefix += "MiningSubDomains.txt_"
                    if domain in spam_sub_domains_data:
                        prefix += "SpamSubDomains.txt_"
                    if virus_name:
                        prefix = virus_name + "_" + prefix
                    try:
                        # İçerikten filename bilgisi çıkartılıyor
                        filename = response.headers.get("Content-Disposition").split("filename=")[1].strip().strip('"')
                    except Exception:
                        filename = None
                    if not filename:
                        logging.info("No filename extracted; skipping download.")
                        return "No filename extracted; skipping download."
                    suggested_filename = prefix + filename
                    saved_path = save_executable_file(domain, content, suggested_filename=suggested_filename)
                    if saved_path:
                        logging.info(f"Downloaded and saved file: {saved_path}")
                        return f"Downloaded and saved file: {saved_path}"
            else:
                logging.info("No content downloaded.")
                return "No content downloaded."
        else:
            logging.info(f"Failed to download from {url} (status code: {response.status_code}).")
            return f"Failed to download from {url} (status code: {response.status_code})."
    except Exception as e:
        logging.error(f"Error downloading from {url}: {e}")
        return f"Error downloading from {url}: {e}"

# ---------------------------------------------------------
# WorkerSignals: to report results from a worker
# ---------------------------------------------------------
class WorkerSignals(QObject):
    update_result = Signal(str)
    finished = Signal()

# ---------------------------------------------------------
# DomainWorker: a QRunnable that processes one domain
# ---------------------------------------------------------
class DomainWorker(QRunnable):
    def __init__(self, domain):
        super().__init__()
        self.domain = domain
        self.signals = WorkerSignals()
    @Slot()
    def run(self):
        try:
            result = process_domain(self.domain)
        except Exception as e:
            result = f"Exception processing {self.domain}: {e}"
            logging.error(result)
        self.signals.update_result.emit(result)
        self.signals.finished.emit()

# ---------------------------------------------------------
# Main GUI Class using a dedicated QThreadPool
# ---------------------------------------------------------
class LocalSearchAntivirus(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Zero-Day Malware Collector - Hydra Dragon")
        self.setup_ui()
        # Create our own thread pool (do not use global instance)
        self.thread_pool = QThreadPool()
        self.thread_pool.setMaxThreadCount(100)
        self.remaining_tasks = 0

    def setup_ui(self):
        layout = QVBoxLayout()
        self.setWindowIcon(QIcon("assets/HydraDragonAV.png"))
        info_label = QLabel("Click the button below to start downloading files from your malware domains.")
        layout.addWidget(info_label)
        self.scan_button = QPushButton("Collect Zero-Day Malware Files")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)
        self.setLayout(layout)

    def start_scan(self):
        self.scan_button.setEnabled(False)
        self.result_text.setPlainText("Starting zero-day malware collection...\n")
        # Build the union of domains from every list
        domains_to_scan = set()
        for lst in [malware_domains_data, malware_domains_mail_data,
                    phishing_domains_data, abuse_domains_data,
                    mining_domains_data, spam_domains_data,
                    malware_sub_domains_data, malware_mail_sub_domains_data,
                    phishing_sub_domains_data, abuse_sub_domains_data,
                    mining_sub_domains_data, spam_sub_domains_data]:
            domains_to_scan.update(lst)
        if not domains_to_scan:
            self.result_text.append("No domains found in your malware lists.\n")
            self.scan_button.setEnabled(True)
            return
        self.remaining_tasks = len(domains_to_scan)
        logging.info(f"Starting scan for {self.remaining_tasks} domains.")
        for domain in domains_to_scan:
            worker = DomainWorker(domain)
            worker.signals.update_result.connect(self.append_result)
            worker.signals.finished.connect(self.worker_finished)
            self.thread_pool.start(worker)

    @Slot(str)
    def append_result(self, text):
        self.result_text.append(text)

    @Slot()
    def worker_finished(self):
        self.remaining_tasks -= 1
        if self.remaining_tasks <= 0:
            self.scan_finished()

    def scan_finished(self):
        self.result_text.append("\nCollection completed.")
        self.scan_button.setEnabled(True)
        logging.info("Scan completed.")

# ---------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------
def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(antivirus_style)
    gui = LocalSearchAntivirus()
    gui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

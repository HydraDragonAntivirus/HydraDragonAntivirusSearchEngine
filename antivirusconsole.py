import os
import re
import sys
import json
import ipaddress
import threading
import requests
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty

# Setup directories and logging
log_dir = "log"
output_dir = "output"
default_bulk = os.path.join(output_dir, "BulkReport.csv")
default_whitelist = os.path.join(output_dir, "WhitelistReport.csv")
os.makedirs(log_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    filename=os.path.join(log_dir, "log.txt"),
    filemode="a"
)

# ---------------------------
# Seed Class: holds IP info
# ---------------------------
class Seed:
    def __init__(self, ip, source_type, version, port=None, source_url=None):
        self.ip = ip.lower()
        # source_type: "malicious", "ddos", "phishing", or "benign"
        self.source_type = source_type  
        self.version = version  # "ipv4" or "ipv6"
        self.port = port        
        self.source_url = source_url if source_url else self.get_url()

    def get_url(self):
        return f"http://{self.ip}:{self.port}" if self.port else f"http://{self.ip}"

# ------------------------------------------
# ScannerWorker: manages the scanning process
# using a ThreadPoolExecutor for concurrency
# ------------------------------------------
class ScannerWorker:
    def __init__(self, settings):
        self.settings = settings
        self.max_workers = int(settings.get("MaxThreads", 100))
        self.user_csv_max_lines = int(settings.get("CsvMaxLines", 10000))
        self.csv_max_lines = self.user_csv_max_lines if self.user_csv_max_lines <= 10000 else 10000
        self.csv_max_size = int(settings.get("CsvMaxSize", 2097152))
        if self.user_csv_max_lines > 10000:
            self.log(f"CsvMaxLines set to {self.user_csv_max_lines} but will be enforced as 10,000 per file due to limits.")
        self.comment_template = settings.get(
            "CommentTemplate",
            "Related with ip address detected (Source IP: {ip}, Source URL: {source_url}, Discovered URL: {discovered_url}, Verdict: {verdict})"
        )

        # Duplicate allowance flags
        self.allow_duplicate_whitelist_ipv4 = settings.get("AllowDuplicateWhitelistIPv4", False)
        self.allow_duplicate_whitelist_ipv6 = settings.get("AllowDuplicateWhitelistIPv6", False)
        self.allow_duplicate_phishing_ipv4  = settings.get("AllowDuplicatePhishingIPv4", False)
        self.allow_duplicate_phishing_ipv6  = settings.get("AllowDuplicatePhishingIPv6", False)
        self.allow_duplicate_ddos_ipv4      = settings.get("AllowDuplicateDDoSIPv4", False)
        self.allow_duplicate_ddos_ipv6      = settings.get("AllowDuplicateDDoSIPv6", False)
        self.allow_duplicate_malicious_ipv4 = settings.get("AllowDuplicateMaliciousIPv4", False)
        self.allow_duplicate_malicious_ipv6 = settings.get("AllowDuplicateMaliciousIPv6", False)
        self.allow_auto_verdict = settings.get("AllowAutoVerdict", True)
        self.request_timeout = int(settings.get("RequestTimeout", 10))

        # Duplicate file paths
        self.duplicate_whitelist_file_ipv4 = settings.get("DuplicateWhitelistFileIPv4", "")
        self.duplicate_whitelist_file_ipv6 = settings.get("DuplicateWhitelistFileIPv6", "")
        self.duplicate_phishing_file_ipv4  = settings.get("DuplicatePhishingFileIPv4", "")
        self.duplicate_phishing_file_ipv6  = settings.get("DuplicatePhishingFileIPv6", "")
        self.duplicate_ddos_file_ipv4      = settings.get("DuplicateDDoSFileIPv4", "")
        self.duplicate_ddos_file_ipv6      = settings.get("DuplicateDDoSFileIPv6", "")
        self.duplicate_malicious_file_ipv4 = settings.get("DuplicateMaliciousFileIPv4", "")
        self.duplicate_malicious_file_ipv6 = settings.get("DuplicateMaliciousFileIPv6", "")

        # File lists (comma-separated paths)
        self.malware_files_ipv4 = [x.strip() for x in settings.get("MalwareFilesIPv4", "").split(",") if x.strip()]
        self.malware_files_ipv6 = [x.strip() for x in settings.get("MalwareFilesIPv6", "").split(",") if x.strip()]
        self.ddos_files_ipv4 = [x.strip() for x in settings.get("DDoSFilesIPv4", "").split(",") if x.strip()]
        self.ddos_files_ipv6 = [x.strip() for x in settings.get("DDoSFilesIPv6", "").split(",") if x.strip()]
        self.phishing_files_ipv4 = [x.strip() for x in settings.get("PhishingFilesIPv4", "").split(",") if x.strip()]
        self.phishing_files_ipv6 = [x.strip() for x in settings.get("PhishingFilesIPv6", "").split(",") if x.strip()]
        self.whitelist_files_ipv4 = [x.strip() for x in settings.get("WhiteListFilesIPv4", "").split(",") if x.strip()]
        self.whitelist_files_ipv6 = [x.strip() for x in settings.get("WhiteListFilesIPv6", "").split(",") if x.strip()]

        # Category file paths
        self.whitelist_path_ipv4 = settings.get("WhiteListPathIPv4", settings.get("WhiteListPath", ""))
        self.whitelist_path_ipv6 = settings.get("WhiteListPathIPv6", settings.get("WhiteListPath", ""))
        self.malware_path_ipv4 = settings.get("MalwarePathIPv4", settings.get("MalwarePath", ""))
        self.malware_path_ipv6 = settings.get("MalwarePathIPv6", settings.get("MalwarePath", ""))
        self.ddos_path_ipv4 = settings.get("DDoSPathIPv4", settings.get("DDoSPath", ""))
        self.ddos_path_ipv6 = settings.get("DDoSPathIPv6", settings.get("DDoSPath", ""))
        self.phishing_path_ipv4 = settings.get("PhishingPathIPv4", settings.get("PhishingPath", ""))
        self.phishing_path_ipv6 = settings.get("PhishingPathIPv6", settings.get("PhishingPath", ""))

        # Categories for CSV output
        self.cat_malicious = settings.get("CategoryMalicious", "20")
        self.cat_ddos = settings.get("CategoryDDoS", "18")
        self.cat_phishing = settings.get("CategoryPhishing", "7")

        # Output CSV file paths
        self.out_bulk_csv = settings.get("OutputFile", default_bulk)
        self.out_whitelist_csv = settings.get("WhiteListOutputFile", default_whitelist)

        self.my_public_ip = None
        self.lock = threading.Lock()
        self.cancelled = False

        # Tracking duplicates and visited IPs
        self.seen_whitelist_ipv4 = set()
        self.seen_whitelist_ipv6 = set()
        self.seen_phishing_ipv4  = set()
        self.seen_phishing_ipv6  = set()
        self.seen_ddos_ipv4      = set()
        self.seen_ddos_ipv6      = set()
        self.seen_malicious_ipv4 = set()
        self.seen_malicious_ipv6 = set()
        self.visited_ips = set()

        # CSV file rotation variables
        self.bulk_file_index = 0
        self.whitelist_file_index = 0
        self.bulk_line_count = 0
        self.whitelist_line_count = 0
        self.bulk_file = None
        self.whitelist_file = None
        self.bulk_file_size = 0
        self.whitelist_file_size = 0

        # Progress counters
        self.processed_count = 0
        self.total_seeds = 0

        # Create a ThreadPoolExecutor for handling tasks concurrently
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)

    def log(self, message):
        print(message)
        logging.info(message)

    def update_progress(self):
        with self.lock:
            total = self.total_seeds if self.total_seeds > 0 else 1
            percent = (self.processed_count / total * 100)
        self.log(f"Progress: {self.processed_count}/{self.total_seeds} ({percent:.0f}%)")

    def open_csv_files(self):
        bulk_dir = os.path.dirname(self.out_bulk_csv)
        if bulk_dir and not os.path.exists(bulk_dir):
            os.makedirs(bulk_dir, exist_ok=True)
        whitelist_dir = os.path.dirname(self.out_whitelist_csv)
        if whitelist_dir and not os.path.exists(whitelist_dir):
            os.makedirs(whitelist_dir, exist_ok=True)
        self.bulk_file_index = 0
        self.whitelist_file_index = 0
        header = "IP,Categories,ReportDate,Comment\n"
        self.bulk_line_count = 1
        self.whitelist_line_count = 1
        self.bulk_file = open(self.out_bulk_csv, "w", encoding="utf-8")
        self.whitelist_file = open(self.out_whitelist_csv, "w", encoding="utf-8")
        self.bulk_file.write(header)
        self.whitelist_file.write(header)
        self.bulk_file.flush()
        self.whitelist_file.flush()
        self.bulk_file_size = len(header.encode("utf-8"))
        self.whitelist_file_size = len(header.encode("utf-8"))

    def close_csv_files(self):
        if self.bulk_file:
            self.bulk_file.close()
        if self.whitelist_file:
            self.whitelist_file.close()

    def write_bulk_line(self, line):
        with self.lock:
            line_bytes = len(line.encode("utf-8"))
            # Rotate file if limits are reached
            if self.bulk_line_count >= self.csv_max_lines or (self.bulk_file_size + line_bytes) >= self.csv_max_size:
                self.bulk_file.close()
                self.bulk_file_index += 1
                base, ext = os.path.splitext(self.out_bulk_csv)
                new_filename = f"{base}_{self.bulk_file_index}{ext}"
                self.bulk_file = open(new_filename, "w", encoding="utf-8")
                header = "IP,Categories,ReportDate,Comment\n"
                self.bulk_file.write(header)
                self.bulk_file.flush()
                self.bulk_line_count = 1
                self.bulk_file_size = len(header.encode("utf-8"))
                self.log(f"Switched to new bulk file: {new_filename}")
            self.bulk_file.write(line)
            self.bulk_file.flush()
            self.bulk_line_count += 1
            self.bulk_file_size += line_bytes

    def write_whitelist_line(self, line):
        with self.lock:
            self.whitelist_file.write(line)
            self.whitelist_file.flush()
            self.whitelist_line_count += 1
            self.whitelist_file_size += len(line.encode("utf-8"))

    def run_scan(self):
        self.log("Loading definitions...")
        self.my_public_ip = self.get_my_public_ip()
        seeds = self.load_seeds()
        if not seeds:
            self.log("No seed IP addresses found.")
            return
        with self.lock:
            self.total_seeds = len(seeds)
        self.log(f"Starting with {len(seeds)} initial seeds.")
        self.open_csv_files()

        # Submit initial seeds to the executor
        for seed in seeds:
            self.executor.submit(self.process_seed, seed)

        self.executor.shutdown(wait=True)
        self.close_csv_files()
        self.log("Scan completed.")

    def handle_duplicate(self, category_key, seed):
        duplicate_file = ""
        if category_key == "whitelist_ipv4":
            duplicate_file = self.duplicate_whitelist_file_ipv4
        elif category_key == "whitelist_ipv6":
            duplicate_file = self.duplicate_whitelist_file_ipv6
        elif category_key == "phishing_ipv4":
            duplicate_file = self.duplicate_phishing_file_ipv4
        elif category_key == "phishing_ipv6":
            duplicate_file = self.duplicate_phishing_file_ipv6
        elif category_key == "ddos_ipv4":
            duplicate_file = self.duplicate_ddos_file_ipv4
        elif category_key == "ddos_ipv6":
            duplicate_file = self.duplicate_ddos_file_ipv6
        elif category_key == "malicious_ipv4":
            duplicate_file = self.duplicate_malicious_file_ipv4
        elif category_key == "malicious_ipv6":
            duplicate_file = self.duplicate_malicious_file_ipv6

        if duplicate_file:
            try:
                with open(duplicate_file, "a", encoding="utf-8") as f:
                    report_date = datetime.now(timezone.utc).isoformat()
                    # For duplicates, we use the seed's URL as the discovered URL.
                    comment = self.comment_template.format(
                        ip=seed.ip,
                        source_url=seed.source_url,
                        discovered_url=seed.get_url(),
                        verdict=seed.source_type
                    )
                    line = f'{seed.ip},"{seed.source_type}",{report_date},"{comment}"\n'
                    f.write(line)
            except Exception as e:
                self.log(f"Error writing duplicate to {duplicate_file}: {e}")

    def process_seed(self, seed):
        if self.cancelled:
            return

        # Check for category-specific duplicates
        category = seed.source_type.lower()
        if category.startswith("benign"):
            flag = self.allow_duplicate_whitelist_ipv4 if seed.version == "ipv4" else self.allow_duplicate_whitelist_ipv6
            seen_set = self.seen_whitelist_ipv4 if seed.version == "ipv4" else self.seen_whitelist_ipv6
        elif "phishing" in category:
            flag = self.allow_duplicate_phishing_ipv4 if seed.version == "ipv4" else self.allow_duplicate_phishing_ipv6
            seen_set = self.seen_phishing_ipv4 if seed.version == "ipv4" else self.seen_phishing_ipv6
        elif "ddos" in category:
            flag = self.allow_duplicate_ddos_ipv4 if seed.version == "ipv4" else self.allow_duplicate_ddos_ipv6
            seen_set = self.seen_ddos_ipv4 if seed.version == "ipv4" else self.seen_ddos_ipv6
        elif "malicious" in category:
            flag = self.allow_duplicate_malicious_ipv4 if seed.version == "ipv4" else self.allow_duplicate_malicious_ipv6
            seen_set = self.seen_malicious_ipv4 if seed.version == "ipv4" else self.seen_malicious_ipv6
        else:
            flag = False
            seen_set = set()

        with self.lock:
            if seed.ip in seen_set:
                if not flag:
                    self.log(f"Skipping duplicate {seed.ip} in category {category}")
                    return
                else:
                    self.log(f"Duplicate allowed for {seed.ip} in category {category}")
                    self.handle_duplicate(category, seed)
            else:
                seen_set.add(seed.ip)

        with self.lock:
            if seed.ip in self.visited_ips:
                self.log(f"Already processed {seed.ip} globally, skipping.")
                return
            self.visited_ips.add(seed.ip)

        self.log(f"Processing: {seed.get_url()}")
        try:
            response = requests.get(seed.get_url(), timeout=self.request_timeout)
            final_url = response.url
        except Exception as e:
            self.log(f"Error visiting {seed.get_url()}: {e}")
            with self.lock:
                self.processed_count += 1
                self.update_progress()
            return

        if response.status_code != 200:
            self.log(f"Skipping {seed.get_url()} due to status {response.status_code}")
            with self.lock:
                self.processed_count += 1
                self.update_progress()
            return

        content = response.text
        if not content:
            self.log(f"No content from {seed.get_url()}")
            with self.lock:
                self.processed_count += 1
                self.update_progress()
            return

        self.log(f"Visited: {seed.get_url()} with final URL: {final_url}")

        # Write CSV entry based on category
        report_date = datetime.now(timezone.utc).isoformat()
        if seed.source_type.lower() == "benign":
            comment = self.comment_template.format(
                ip=seed.ip,
                source_url=seed.source_url,
                discovered_url=final_url,
                verdict=seed.source_type
            )
            self.write_whitelist_line(f'{seed.ip},"",{report_date},"{comment}"\n')
        else:
            if seed.source_type.lower() == "malicious":
                category_label = self.cat_malicious
            elif seed.source_type.lower() == "ddos":
                category_label = self.cat_ddos
            elif seed.source_type.lower() == "phishing":
                category_label = self.cat_phishing
            else:
                category_label = ""
            comment = self.comment_template.format(
                ip=seed.ip,
                source_url=seed.source_url,
                discovered_url=final_url,
                verdict=seed.source_type
            )
            self.write_bulk_line(f'{seed.ip},"{category_label}",{report_date},"{comment}"\n')

        # Discover new IPs from the page content
        found_ips = self.extract_ip_and_port(content)
        for ip, port, ip_version in found_ips:
            if self.my_public_ip and ip == self.my_public_ip:
                self.log(f"Skipping my own public IP: {ip}")
                continue

            final_hostname = urlparse(final_url).hostname
            if ip == seed.ip or (final_hostname and ip == final_hostname):
                self.log(f"Skipping discovered IP {ip} because it matches the source.")
                continue

            with self.lock:
                if ip in self.visited_ips:
                    self.log(f"Skipping discovered IP {ip} because it is already processed.")
                    continue
                self.total_seeds += 1

            if seed.source_type.lower() == "benign":
                new_source_type = "benign (auto verdict 2)" if self.is_active_and_static(ip, port) else "benign (auto verdict 3)"
            else:
                new_source_type = "benign (auto verdict 1)" if not self.is_active_and_static(ip, port) else seed.source_type

            new_seed = Seed(ip, new_source_type, ip_version, port=port, source_url=final_url)
            self.log(f"Recursively processing new seed: {new_seed.get_url()}")
            self.executor.submit(self.process_seed, new_seed)

        with self.lock:
            self.processed_count += 1
            self.update_progress()

    def get_my_public_ip(self):
        try:
            response = requests.get("https://api.ipify.org", timeout=self.request_timeout)
            ip = response.text.strip()
            self.log(f"My public IP is {ip}")
            return ip
        except Exception as e:
            self.log(f"Could not determine public IP: {e}")
            return None

    def is_active_and_static(self, ip, port, timeout=None):
        if timeout is None:
            timeout = self.request_timeout
        url = f"http://{ip}" + (f":{port}" if port else "")
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            if response.status_code != 200:
                return False
            parsed_url = urlparse(response.url)
            final_hostname = parsed_url.hostname
            final_port = parsed_url.port if parsed_url.port else 80
            expected_port = port if port else 80
            if final_hostname and self.is_valid_ip(final_hostname) and final_hostname == ip and final_port == expected_port:
                return True
            return False
        except Exception as e:
            self.log(f"Active/static check failed for {url}: {e}")
            return False

    def is_valid_ip(self, ip_string):
        try:
            ip_obj = ipaddress.ip_address(ip_string)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
                return None
            return "ipv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "ipv6"
        except ValueError:
            return None

    def extract_ip_and_port(self, text):
        found_ips = []
        ipv4_pattern = re.compile(
            r'\b(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::(?P<port>[0-9]{1,5}))?\b'
        )
        ipv6_bracket_pattern = re.compile(
            r'\[(?P<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})\](?::(?P<port>[0-9]{1,5}))?'
        )
        ipv6_pattern = re.compile(
            r'\b(?P<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})\b'
        )
        for match in ipv6_bracket_pattern.finditer(text):
            ip = match.group("ip")
            port_str = match.group("port")
            port = int(port_str) if port_str and port_str.isdigit() and 1 <= int(port_str) <= 65535 else None
            if self.is_valid_ip(ip):
                found_ips.append((ip, port, "ipv6"))
        for match in ipv4_pattern.finditer(text):
            ip = match.group("ip")
            port_str = match.group("port")
            port = int(port_str) if port_str and port_str.isdigit() and 1 <= int(port_str) <= 65535 else None
            if self.is_valid_ip(ip):
                found_ips.append((ip, port, "ipv4"))
        for match in ipv6_pattern.finditer(text):
            ip = match.group("ip")
            if any(existing[0] == ip for existing in found_ips):
                continue
            if self.is_valid_ip(ip):
                found_ips.append((ip, None, "ipv6"))
        return found_ips

    def load_lines(self, path):
        s = set()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip().lower()
                    if ':' in line:
                        ip, _ = line.rsplit(":", 1)
                    else:
                        ip = line
                    if ip and self.is_valid_ip(ip):
                        s.add(ip)
        self.log(f"Loaded {len(s)} valid IPs from {path}")
        return s

    def load_seeds(self):
        seeds = []
        file_ip_cache = {}

        def get_ips_from_file(file):
            if file not in file_ip_cache:
                file_ip_cache[file] = self.load_lines(file)
            return file_ip_cache[file]

        # Load seeds from whitelist, phishing, ddos, and malware files.
        for file in self.whitelist_files_ipv6:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "benign", "ipv6", source_url=""))
        for file in self.whitelist_files_ipv4:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "benign", "ipv4", source_url=""))
        for file in self.phishing_files_ipv6:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "phishing", "ipv6", source_url=""))
        for file in self.phishing_files_ipv4:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "phishing", "ipv4", source_url=""))
        for file in self.ddos_files_ipv6:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "ddos", "ipv6", source_url=""))
        for file in self.ddos_files_ipv4:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "ddos", "ipv4", source_url=""))
        for file in self.malware_files_ipv6:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "malicious", "ipv6", source_url=""))
        for file in self.malware_files_ipv4:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "malicious", "ipv4", source_url=""))

        self.log(f"Total valid seeds loaded: {len(seeds)}")
        return seeds

# ---------------------------
# Main entry point
# ---------------------------
def main():
    # Default settings for the console version.
    settings = {
        "MaxThreads": 100,
        "CsvMaxLines": 10000,
        "CsvMaxSize": 2097152,
        "OutputFile": default_bulk,
        "WhiteListOutputFile": default_whitelist,
        "CategoryMalicious": "20",
        "CategoryPhishing": "7",
        "CategoryDDoS": "18",
        "CommentTemplate": "Related with ip address detected (Source IP: {ip}, Source URL: {source_url}, Discovered URL: {discovered_url}, Verdict: {verdict})",
        "MalwareFilesIPv6": "website/IPv6Malware.txt",
        "MalwareFilesIPv4": "website/IPv4Malware.txt",
        "DDoSFilesIPv6": "",
        "DDoSFilesIPv4": "website/IPv4DDoS.txt",
        "PhishingFilesIPv6": "",
        "PhishingFilesIPv4": "website/IPv4PhishingActive.txt, website/IPv4PhishingInActive.txt",
        "WhiteListFilesIPv6": "website/IPv6WhiteList.txt",
        "WhiteListFilesIPv4": "website/IPv4WhiteList.txt",
        "WhiteListPathIPv4": "website/IPv4WhiteList.txt",
        "WhiteListPathIPv6": "website/IPv6WhiteList.txt",
        "PhishingPathIPv4": "website/IPv4Phishing.txt",
        "PhishingPathIPv6": "website/IPv6Phishing.txt",
        "DDoSPathIPv4": "website/IPv4DDoS.txt",
        "DDoSPathIPv6": "website/IPv6DDoS.txt",
        "MalwarePathIPv4": "website/IPv4Malware.txt",
        "MalwarePathIPv6": "website/IPv6Malware.txt",
        "AllowDuplicateWhitelistIPv4": False,
        "AllowDuplicateWhitelistIPv6": False,
        "AllowDuplicatePhishingIPv4": False,
        "AllowDuplicatePhishingIPv6": False,
        "AllowDuplicateDDoSIPv4": False,
        "AllowDuplicateDDoSIPv6": False,
        "AllowDuplicateMaliciousIPv4": False,
        "AllowDuplicateMaliciousIPv6": False,
        "DuplicateWhitelistFileIPv4": "output/whitelist_ipv4_duplicates.csv",
        "DuplicateWhitelistFileIPv6": "output/whitelist_ipv6_duplicates.csv",
        "DuplicatePhishingFileIPv4": "output/phishing_ipv4_duplicates.csv",
        "DuplicatePhishingFileIPv6": "output/phishing_ipv6_duplicates.csv",
        "DuplicateDDoSFileIPv4": "output/ddos_ipv4_duplicates.csv",
        "DuplicateDDoSFileIPv6": "output/ddos_ipv6_duplicates.csv",
        "DuplicateMaliciousFileIPv4": "output/malicious_ipv4_duplicates.csv",
        "DuplicateMaliciousFileIPv6": "output/malicious_ipv6_duplicates.csv",
        "AllowAutoVerdict": True,
        "RequestTimeout": 10
    }

    worker = ScannerWorker(settings)
    try:
        worker.run_scan()
    except KeyboardInterrupt:
        worker.cancelled = True
        worker.log("Scan cancelled by user.")

if __name__ == "__main__":
    main()

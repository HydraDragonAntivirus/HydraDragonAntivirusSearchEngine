import os
import re
import sys
import json
import ipaddress
import threading
import queue
import time
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
import requests
import logging
from bs4 import BeautifulSoup
from tqdm import tqdm  # Progress bar

# Directories and default file paths
log_dir = "log"
output_dir = "output"
default_bulk = os.path.join(output_dir, "BulkReport.csv")
default_whitelist = os.path.join(output_dir, "WhitelistReport.csv")
os.makedirs(log_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)

# -----------------------------
# Configure Logging
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    filename=os.path.join(log_dir, "antivirus.log"),
    filemode="a"
)

log_file = os.path.join(log_dir, "antiviruscritical.log")
sys.stdout = open(log_file, "w", encoding="utf-8", errors="ignore")
sys.stderr = open(log_file, "w", encoding="utf-8", errors="ignore")

def compute_content_similarity(text1, text2):
    import difflib
    ratio = difflib.SequenceMatcher(None, text1, text2).ratio()
    return ratio * 100

# -----------------------------
# Global Default Settings (Hard-Coded)
# -----------------------------
DEFAULT_SETTINGS = {
    "MaxThreads": 1000,
    "CsvMaxLines": 10000,
    "CsvMaxSize": 2097152,
    "CommentTemplateZeroday": "Related with ip address detected by heuristics (Discovered IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict}, HTTP Status: {status}), Zeroday: Yes it's not duplicate",
    "CommentTemplateNoZeroday": "Related with ip address detected by heuristics (Discovered IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict}, HTTP Status: {status}), Zeroday: No it's duplicate",
    "CommentTemplateZerodayUp": "Related with ip address detected by heuristics (Discovered IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict}, HTTP Status: {status}), HTML similarity: {similarity}, Zeroday: Yes it's not duplicate",
    "RequestTimeout": 10,
    "BulkOutputFile": default_bulk,
    "WhiteListOutputFile": default_whitelist,
    "PotentiallyUpBulkOutputFile": os.path.join(output_dir, "potentially_up_bulk.csv"),
    "PotentiallyDownBulkOutputFile": os.path.join(output_dir, "potentially_down_bulk.csv"),
    "PotentiallyUpWhiteListOutputFile": os.path.join(output_dir, "potentially_up_whitelist.csv"),
    "PotentiallyDownWhiteListOutputFile": os.path.join(output_dir, "potentially_down_whitelist.csv"),
    "WinErrorBulkOutputFile": os.path.join(output_dir, "winerror_bulk.csv"),
    "WinErrorWhitelistOutputFile": os.path.join(output_dir, "winerror_whitelist.csv"),
    "BulkDuplicateOutputFile": os.path.join(output_dir, "bulk_duplicates.csv"),
    "WhitelistDuplicateOutputFile": os.path.join(output_dir, "whitelist_duplicates.csv"),
    "ZeroDayExecutableDetection": "true",
    "ZeroDayExecutableOutputFile": os.path.join(output_dir, "ZeroDayExecutables.csv"),
    "HTTPUpCodes": "100,101,102,200,201,202,203,204,205,206,207,208,226,429",
    "HTTPPotentiallyDownCodes": "400,402,404,409,410,412,414,415,416,451",
    "HTTPPotentiallyUpCodes": "000,300,301,302,303,304,305,307,308,403,405,406,407,408,411,413,417,418,421,422,423,424,426,428,431,500,501,502,503,504,505,506,507,508,510,511",
    "CategoryPhishing": "7",
    "CategoryDDoS": "4",
    "CategoryBruteForce": "18",
    "CategorySpam": "10",
    "CategoryMalicious": "20",
    "WhiteListFilesIPv6": "website/IPv6WhiteList.txt",
    "WhiteListFilesIPv4": "website/IPv4WhiteList.txt",
    "PhishingFilesIPv6": "",
    "PhishingFilesIPv4Active": "website/IPv4PhishingActive.txt, website/IPv4PhishingInActive.txt",
    "PhishingFilesIPv4InActive": "website/IPv4PhishingActive.txt, website/IPv4PhishingInActive.txt",
    "DDoSFilesIPv6": "website/IPv6DDoS.txt",
    "DDoSFilesIPv4": "website/IPv4DDoS.txt",
    "BruteForceFilesIPv6": "",
    "BruteForceFilesIPv4": "website/IPv4BruteForce.txt",
    "SpamFilesIPv6": "website/IPv6Spam.txt",
    "SpamFilesIPv4": "website/IPv4Spam.txt",
    "MalwareFilesIPv6": "website/IPv6Malware.txt",
    "MalwareFilesIPv4": "website/IPv4Malware.txt",
}

def load_settings_from_file():
    settings_folder = "settings"
    settings_file = "settings.json"
    settings_path = os.path.join(settings_folder, settings_file)
    if os.path.exists(settings_path):
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                settings = json.load(f)
                logging.info("Loaded settings from %s", settings_path)
                return settings
        except Exception as e:
            logging.error("Error reading settings from file: %s", e)
    else:
        logging.info("Settings file %s not found, using default settings", settings_path)
    return DEFAULT_SETTINGS

SETTINGS = load_settings_from_file()

# -----------------------------
# Seed Class (metadata only)
# -----------------------------
class Seed:
    def __init__(self, ip, source_type, port=None):
        self.ip = ip.lower()
        self.source_type = source_type  # e.g., "malicious_ipv4", "phishing_ipv6", etc.
        self.port = port

    def get_url(self):
        return f"http://{self.ip}:{self.port}" if self.port else f"http://{self.ip}"

# -----------------------------
# ScannerWorker: Main scanning logic
# -----------------------------
class ScannerWorker:
    def __init__(self, settings=None):
        self.settings = settings if settings is not None else SETTINGS
        self.max_workers = int(self.settings["MaxThreads"])
        self.user_csv_max_lines = int(self.settings["CsvMaxLines"])
        self.csv_max_lines = self.user_csv_max_lines if self.user_csv_max_lines <= 10000 else 10000
        self.csv_max_size = int(self.settings["CsvMaxSize"])
        if self.user_csv_max_lines > 10000:
            logging.info(f"CsvMaxLines set to {self.user_csv_max_lines} but enforced as 10,000.")
        self.comment_template_zeroday = self.settings["CommentTemplateZeroday"]
        self.comment_template_nozeroday = self.settings["CommentTemplateNoZeroday"]
        self.comment_template_zeroday_up = self.settings["CommentTemplateZerodayUp"]
        self.request_timeout = int(self.settings["RequestTimeout"])
        self.out_bulk_csv = self.settings["BulkOutputFile"]
        self.out_whitelist_csv = self.settings["WhiteListOutputFile"]
        self.out_potentially_up_bulk_csv = self.settings["PotentiallyUpBulkOutputFile"]
        self.out_potentially_down_bulk_csv = self.settings["PotentiallyDownBulkOutputFile"]
        self.out_potentially_up_whitelist_csv = self.settings["PotentiallyUpWhiteListOutputFile"]
        self.out_potentially_down_whitelist_csv = self.settings["PotentiallyDownWhiteListOutputFile"]
        self.out_winerror_bulk_csv = self.settings["WinErrorBulkOutputFile"]
        self.out_winerror_whitelist_csv = self.settings["WinErrorWhitelistOutputFile"]
        self.out_bulk_duplicate_csv = self.settings["BulkDuplicateOutputFile"]
        self.out_whitelist_duplicate_csv = self.settings["WhitelistDuplicateOutputFile"]
        self.zeroday_exe_enabled = self.settings["ZeroDayExecutableDetection"].lower() == "true"
        self.out_zeroday_exe_csv = self.settings["ZeroDayExecutableOutputFile"]

        self.my_public_ip = None
        self.lock = threading.Lock()
        self.cancelled = False
        self.visited_ips = set()  # to keep track of processed IPs
        self.processed_count = 0

        # Use a thread-safe queue for seeds
        self.seed_queue = queue.Queue()

        # We'll set up tqdm later (after seeds are loaded)
        self.progress_bar = None

    def log(self, message):
        logging.info(message)
        tqdm.write(message)

    def open_csv_files(self):
        unique_files = {
            self.out_bulk_csv,
            self.out_whitelist_csv,
            self.out_potentially_up_whitelist_csv,
            self.out_potentially_down_whitelist_csv,
            self.out_winerror_bulk_csv,
            self.out_winerror_whitelist_csv,
            self.out_bulk_duplicate_csv,
            self.out_whitelist_duplicate_csv
        }
        for filename in unique_files:
            directory = os.path.dirname(filename)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
        header = "IP,Categories,ReportDate,Comment\n"

        self.bulk_file = open(self.out_bulk_csv, "w", encoding="utf-8")
        self.whitelist_file = open(self.out_whitelist_csv, "w", encoding="utf-8")
        self.potentially_up_whitelist_file = open(self.out_potentially_up_whitelist_csv, "w", encoding="utf-8")
        self.potentially_down_whitelist_file = open(self.out_potentially_down_whitelist_csv, "w", encoding="utf-8")
        self.out_winerror_bulk_file = open(self.out_winerror_bulk_csv, "w", encoding="utf-8")
        self.out_winerror_whitelist_file = open(self.out_winerror_whitelist_csv, "w", encoding="utf-8")
        for file in [self.bulk_file, self.whitelist_file,
                     self.potentially_up_whitelist_file, self.potentially_down_whitelist_file,
                     self.out_winerror_bulk_file, self.out_winerror_whitelist_file]:
            file.write(header)
            file.flush()

        self.bulk_duplicate_file = open(self.out_bulk_duplicate_csv, "w", encoding="utf-8")
        self.bulk_duplicate_file.write(header)
        self.bulk_duplicate_file.flush()
        self.bulk_duplicate_line_count = 1
        self.bulk_duplicate_file_size = len(header.encode("utf-8"))
        self.bulk_duplicate_file_index = 0

        self.whitelist_duplicate_file = open(self.out_whitelist_duplicate_csv, "w", encoding="utf-8")
        self.whitelist_duplicate_file.write(header)
        self.whitelist_duplicate_file.flush()
        self.whitelist_duplicate_line_count = 1
        self.whitelist_duplicate_file_size = len(header.encode("utf-8"))
        self.whitelist_duplicate_file_index = 0

        if self.zeroday_exe_enabled:
            self.zeroday_exe_file = open(self.out_zeroday_exe_csv, "w", encoding="utf-8")

    def close_csv_files(self):
        for f in [getattr(self, attr, None) for attr in [
            "bulk_file", "whitelist_file", "potentially_up_whitelist_file",
            "potentially_down_whitelist_file", "out_winerror_bulk_file", "out_winerror_whitelist_file",
            "bulk_duplicate_file", "whitelist_duplicate_file"
        ]]:
            if f:
                f.close()
        if self.zeroday_exe_enabled and hasattr(self, 'zeroday_exe_file') and self.zeroday_exe_file:
            self.zeroday_exe_file.close()

    def check_zeroday_executable(self, url, originating_ip):
        try:
            response = requests.get(url, timeout=self.request_timeout, stream=True)
            if response.status_code == 200:
                header_bytes = response.raw.read(4)
                if header_bytes.startswith(b'MZ'):
                    report_date = datetime.now(timezone.utc).isoformat()
                    comment = "ZeroDay Executable detected (MZ signature)"
                    line = f'{originating_ip},{url},{report_date},"{comment}"\n'
                    self.write_zeroday_exe_line(line)
                    self.log(f"ZeroDay executable detected (MZ) at {url}")
                elif header_bytes == b'\x7FELF':
                    report_date = datetime.now(timezone.utc).isoformat()
                    comment = "ZeroDay Executable detected (ELF signature)"
                    line = f'{originating_ip},{url},{report_date},"{comment}"\n'
                    self.write_zeroday_exe_line(line)
                    self.log(f"ZeroDay executable detected (ELF) at {url}")
        except Exception as e:
            self.log(f"Error in ZeroDay executable check for {url}: {e}")

    def write_zeroday_exe_line(self, line):
        with self.lock:
            self.zeroday_exe_file.write(line)
            self.zeroday_exe_file.flush()

    def write_winerror_whitelist_line(self, line):
        with self.lock:
            self.out_winerror_whitelist_file.write(line)
            self.out_winerror_whitelist_file.flush()

    def write_winerror_bulk_line(self, line):
        with self.lock:
            line_bytes = len(line.encode("utf-8"))
            if getattr(self, "out_winerror_bulk_line_count", 1) >= self.csv_max_lines:
                self.out_winerror_bulk_file.close()
                self.out_winerror_bulk_file_index += 1
                base, ext = os.path.splitext(self.out_winerror_bulk_csv)
                new_filename = f"{base}_{self.out_winerror_bulk_file_index}{ext}"
                self.out_winerror_bulk_file = open(new_filename, "w", encoding="utf-8")
                header = "IP,Categories,ReportDate,Comment\n"
                self.out_winerror_bulk_file.write(header)
                self.out_winerror_bulk_file.flush()
                self.out_winerror_bulk_line_count = 1
                self.log(f"WinError Bulk file rotated; new file: {new_filename}")
            self.out_winerror_bulk_file.write(line)
            self.out_winerror_bulk_file.flush()
            self.out_winerror_bulk_line_count = getattr(self, "out_winerror_bulk_line_count", 1) + 1

    def write_bulk_duplicate_line(self, line):
        with self.lock:
            line_bytes = len(line.encode("utf-8"))
            if self.bulk_duplicate_line_count >= self.csv_max_lines or (self.bulk_duplicate_file_size + line_bytes) >= self.csv_max_size:
                self.bulk_duplicate_file.close()
                self.bulk_duplicate_file_index += 1
                base, ext = os.path.splitext(self.out_bulk_duplicate_csv)
                new_filename = f"{base}_{self.bulk_duplicate_file_index}{ext}"
                self.bulk_duplicate_file = open(new_filename, "w", encoding="utf-8")
                header = "IP,Categories,ReportDate,Comment\n"
                self.bulk_duplicate_file.write(header)
                self.bulk_duplicate_file.flush()
                self.bulk_duplicate_line_count = 1
                self.bulk_duplicate_file_size = len(header.encode("utf-8"))
                self.log(f"Bulk duplicate file rotated; new file: {new_filename}")
            self.bulk_duplicate_file.write(line)
            self.bulk_duplicate_file.flush()
            self.bulk_duplicate_line_count += 1
            self.bulk_duplicate_file_size += line_bytes

    def write_whitelist_duplicate_line(self, line):
        with self.lock:
            line_bytes = len(line.encode("utf-8"))
            if self.whitelist_duplicate_line_count >= self.csv_max_lines or (self.whitelist_duplicate_file_size + line_bytes) >= self.csv_max_size:
                self.whitelist_duplicate_file.close()
                self.whitelist_duplicate_file_index += 1
                base, ext = os.path.splitext(self.out_whitelist_duplicate_csv)
                new_filename = f"{base}_{self.whitelist_duplicate_file_index}{ext}"
                self.whitelist_duplicate_file = open(new_filename, "w", encoding="utf-8")
                header = "IP,Categories,ReportDate,Comment\n"
                self.whitelist_duplicate_file.write(header)
                self.whitelist_duplicate_file.flush()
                self.whitelist_duplicate_line_count = 1
                self.whitelist_duplicate_file_size = len(header.encode("utf-8"))
                self.log(f"Whitelist duplicate file rotated; new file: {new_filename}")
            self.whitelist_duplicate_file.write(line)
            self.whitelist_duplicate_file.flush()
            self.whitelist_duplicate_line_count += 1
            self.whitelist_duplicate_file_size += line_bytes

    def write_potentially_up_bulk_line(self, line):
        with self.lock:
            line_bytes = len(line.encode("utf-8"))
            if getattr(self, "potentially_up_bulk_line_count", 1) >= self.csv_max_lines:
                self.potentially_up_bulk_file.close()
                self.potentially_up_bulk_file_index += 1
                base, ext = os.path.splitext(self.out_potentially_up_bulk_csv)
                new_filename = f"{base}_{self.potentially_up_bulk_file_index}{ext}"
                self.potentially_up_bulk_file = open(new_filename, "w", encoding="utf-8")
                header = "IP,Categories,ReportDate,Comment\n"
                self.potentially_up_bulk_file.write(header)
                self.potentially_up_bulk_file.flush()
                self.potentially_up_bulk_line_count = 1
                self.log(f"Potentially Up Bulk file rotated; new file: {new_filename}")
            self.potentially_up_bulk_file.write(line)
            self.potentially_up_bulk_file.flush()
            self.potentially_up_bulk_line_count = getattr(self, "potentially_up_bulk_line_count", 1) + 1

    def write_potentially_down_bulk_line(self, line):
        with self.lock:
            line_bytes = len(line.encode("utf-8"))
            if getattr(self, "potentially_down_bulk_line_count", 1) >= self.csv_max_lines:
                self.potentially_down_bulk_file.close()
                self.potentially_down_bulk_file_index += 1
                base, ext = os.path.splitext(self.out_potentially_down_bulk_csv)
                new_filename = f"{base}_{self.potentially_down_bulk_file_index}{ext}"
                self.potentially_down_bulk_file = open(new_filename, "w", encoding="utf-8")
                header = "IP,Categories,ReportDate,Comment\n"
                self.potentially_down_bulk_file.write(header)
                self.potentially_down_bulk_file.flush()
                self.potentially_down_bulk_line_count = 1
                self.log(f"Potentially Down Bulk file rotated; new file: {new_filename}")
            self.potentially_down_bulk_file.write(line)
            self.potentially_down_bulk_file.flush()
            self.potentially_down_bulk_line_count = getattr(self, "potentially_down_bulk_line_count", 1) + 1

    def write_potentially_up_whitelist_line(self, line):
        with self.lock:
            self.potentially_up_whitelist_file.write(line)
            self.potentially_up_whitelist_file.flush()

    def write_potentially_down_whitelist_line(self, line):
        with self.lock:
            self.potentially_down_whitelist_file.write(line)
            self.potentially_down_whitelist_file.flush()

    def write_bulk_line(self, line):
        with self.lock:
            line_bytes = len(line.encode("utf-8"))
            if getattr(self, "bulk_line_count", 1) >= self.csv_max_lines:
                self.bulk_file.close()
                self.bulk_file_index += 1
                base, ext = os.path.splitext(self.out_bulk_csv)
                new_filename = f"{base}_{self.bulk_file_index}{ext}"
                self.bulk_file = open(new_filename, "w", encoding="utf-8")
                header = "IP,Categories,ReportDate,Comment\n"
                self.bulk_file.write(header)
                self.bulk_file.flush()
                self.bulk_line_count = 1
                self.log(f"Bulk file rotated; new file: {new_filename}")
            self.bulk_file.write(line)
            self.bulk_file.flush()
            self.bulk_line_count = getattr(self, "bulk_line_count", 1) + 1

    def write_whitelist_line(self, line):
        with self.lock:
            self.whitelist_file.write(line)
            self.whitelist_file.flush()

    def get_my_public_ip(self):
        try:
            response = requests.get("https://api.ipify.org", timeout=self.request_timeout)
            ip = response.text.strip()
            self.log(f"My public IP is {ip}")
            return ip
        except Exception as e:
            self.log(f"Could not determine public IP: {e}")
            return None

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
        ipv4_pattern = re.compile(r'\b(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::(?P<port>[0-9]{1,5}))?\b')
        ipv6_bracket_pattern = re.compile(r'\[(?P<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})(?::(?P<port>[0-9]{1,5}))?')
        ipv6_pattern = re.compile(r'\b(?P<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})\b')
        for match in ipv6_bracket_pattern.finditer(text):
            ip = match.group("ip")
            port_str = match.group("port")
            port = int(port_str) if port_str and port_str.isdigit() and 1 <= int(port_str) <= 65535 else None
            if self.is_valid_ip(ip):
                found_ips.append((ip, port, "ipv6"))
        for match in ipv4_pattern.finditer(text):
            ip = match.group("ip")
            port_str = match.group("port")
            if port_str:
                try:
                    port = int(port_str)
                    if not (1 <= port <= 65535):
                        continue
                except ValueError:
                    continue
            else:
                port = None
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
        entries = []
        # Support multiple files separated by commas
        paths = [p.strip() for p in path.split(",") if p.strip()]
        for single_path in paths:
            if os.path.exists(single_path):
                with open(single_path, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split(",", 1)
                        ip = parts[0].strip().lower()
                        if ip and self.is_valid_ip(ip):
                            entries.append(ip)
                self.log(f"Loaded {len(entries)} valid IP entries from {single_path}")
        return entries

    def load_seeds(self):
        seeds = []
        file_category_mapping = {}

        def add_file(file, source_type):
            if file not in file_category_mapping:
                file_category_mapping[file] = []
            file_category_mapping[file].append(source_type)

        add_file(self.settings["WhiteListFilesIPv6"], "whitelist_ipv6")
        add_file(self.settings["WhiteListFilesIPv4"], "whitelist_ipv4")
        add_file(self.settings["PhishingFilesIPv6"], "phishing_ipv6")
        add_file(self.settings.get("PhishingFilesIPv4Active", ""), "phishing_ipv4_active")
        add_file(self.settings.get("PhishingFilesIPv4InActive", ""), "phishing_ipv4_inactive")
        add_file(self.settings["DDoSFilesIPv6"], "ddos_ipv6")
        add_file(self.settings["DDoSFilesIPv4"], "ddos_ipv4")
        add_file(self.settings["BruteForceFilesIPv6"], "bruteforce_ipv6")
        add_file(self.settings["BruteForceFilesIPv4"], "bruteforce_ipv4")
        add_file(self.settings["SpamFilesIPv6"], "spam_ipv6")
        add_file(self.settings["SpamFilesIPv4"], "spam_ipv4")
        add_file(self.settings["MalwareFilesIPv6"], "malicious_ipv6")
        add_file(self.settings["MalwareFilesIPv4"], "malicious_ipv4")

        results = {}
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_file = {executor.submit(self.load_lines, file): file for file in file_category_mapping}
            for future in concurrent.futures.as_completed(future_to_file):
                file = future_to_file[future]
                try:
                    ips = future.result()
                except Exception as exc:
                    self.log(f"Error loading file {file}: {exc}")
                    ips = []
                results[file] = ips

        for file, ips in results.items():
            for source_type in file_category_mapping[file]:
                for ip in ips:
                    if ip not in self.visited_ips:
                        seeds.append(Seed(ip, source_type))
                        self.visited_ips.add(ip)
        self.log(f"Total valid seeds loaded: {len(seeds)}")
        return seeds

    def is_active_and_static(self, ip, port, timeout=None, category=None, discovered_source_url=None):
        if timeout is None:
            timeout = self.request_timeout
        if self.is_valid_ip(ip) == "ipv6":
            url = f"http://[{ip}]" + (f":{port}" if port else "")
        else:
            url = f"http://{ip}" + (f":{port}" if port else "")
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True)
        except requests.exceptions.Timeout as e:
            self.log(f"Timeout for {url}: {e}")
            return f"TIMEOUT: {e}"
        except requests.exceptions.ConnectionError as e:
            if "[WinError 10061]" in str(e):
                self.log(f"Connection refused (WinError 10061) for {url} – firewall detected.")
                return "up: Firewall detected"
            else:
                self.log(f"Connection error for {url}: {e}")
                return f"WINERROR: {e}"
        except requests.exceptions.RequestException as e:
            self.log(f"Request failed for {url}: {e}")
            return f"WINERROR: {e}"

        code = response.status_code
        code_str = f"{code:03d}"
        http_up_codes = [s.strip() for s in self.settings["HTTPUpCodes"].split(",")]
        http_potentially_down_codes = [s.strip() for s in self.settings["HTTPPotentiallyDownCodes"].split(",")]
        http_potentially_up_codes = [s.strip() for s in self.settings["HTTPPotentiallyUpCodes"].split(",")]

        resource_urls = set()

        if code_str in http_up_codes:
            if response.url.startswith("http://") or response.url.startswith("https://"):
                parsed_ip = urlparse(response.url).hostname
                if parsed_ip and parsed_ip != ip and self.is_valid_ip(parsed_ip):
                    new_seed = Seed(parsed_ip, category, port=port)
                    self.log(f"Queueing redirected IP: {parsed_ip} (Category: {category}) - HTTP {code_str}")
                    self.seed_queue.put(new_seed)
            found_ips = self.extract_ip_and_port(response.text)
            for extracted_ip, extracted_port, ip_version in found_ips:
                new_seed = Seed(extracted_ip, category, port=extracted_port)
                self.log(f"Queueing discovered IP: {extracted_ip} (Category: {category}) - HTTP {code_str}")
                self.seed_queue.put(new_seed)
            soup = BeautifulSoup(response.text, "html.parser")
            for tag in soup.find_all(["script", "link", "img"]):
                attr = "src" if tag.name in ["script", "img"] else "href"
                url_val = tag.get(attr)
                if url_val:
                    resource_urls.add(urljoin(url, url_val))
            for resource_url in resource_urls:
                try:
                    res = requests.get(resource_url, timeout=timeout, allow_redirects=True)
                    res_code_str = f"{res.status_code:03d}"
                    if res_code_str in http_up_codes:
                        resource_ips = self.extract_ip_and_port(res.text)
                        for extracted_ip, extracted_port, ip_version in resource_ips:
                            new_seed = Seed(extracted_ip, category, port=extracted_port)
                            self.log(f"Queueing discovered IP from resource {resource_url}: {extracted_ip} (Category: {category}) - HTTP {code_str}")
                            self.seed_queue.put(new_seed)
                    else:
                        self.log(f"Resource {resource_url} returned HTTP {res.status_code}")
                except Exception:
                    pass
            return f"up: HTTP {code_str}"

        if self.zeroday_exe_enabled:
            for resource_url in resource_urls:
                self.check_zeroday_executable(resource_url, ip)
        elif code_str in http_potentially_up_codes:
            self.log(f"Potentially Up status for {url}: HTTP {code_str}")
            return f"potentially up: HTTP {code_str}"
        elif code_str in http_potentially_down_codes:
            self.log(f"Potentially Down status for {url}: HTTP {code_str}")
            return f"potentially down: HTTP {code_str}"
        else:
            self.log(f"Unhandled HTTP status code {code_str} for {url}")
            return f"unhandled: HTTP {code_str}"

    def process_seed(self, seed, discovered_source_url=None, duplicate_flag=None):
        try:
            if seed.ip.startswith("https://") or seed.ip.startswith("http://"):
                seed.ip = urlparse(seed.ip).hostname
            if self.my_public_ip and seed.ip == self.my_public_ip:
                self.log(f"Skipping my own public IP: {seed.ip}")
                return
            if not self.is_valid_ip(seed.ip):
                self.log(f"Skipping seed with invalid IP: {seed.ip}")
                return
            with self.lock:
                if seed.ip in self.visited_ips and duplicate_flag is None:
                    self.log(f"Skipping {seed.ip} (already visited).")
                    return
                self.visited_ips.add(seed.ip)

            allowed_categories = {
                "whitelist_ipv6", "whitelist_ipv4",
                "phishing_ipv6", "phishing_ipv4_active", "phishing_ipv4_inactive",
                "ddos_ipv6", "ddos_ipv4",
                "bruteforce_ipv6", "bruteforce_ipv4",
                "spam_ipv6", "spam_ipv4",
                "malicious_ipv6", "malicious_ipv4"
            }
            cat = seed.source_type.lower().strip()
            if cat not in allowed_categories:
                self.log(f"Category for {seed.ip} is '{cat}', which is not allowed. Skipping processing.")
                return
            if not discovered_source_url:
                discovered_source_url = seed.get_url()

            category_mapping = {
                "whitelist": "0",
                "phishing": "7",
                "ddos": "4",
                "bruteforce": "18",
                "spam": "10",
                "malicious": "20"
            }
            base_category = seed.source_type.split("_")[0].lower()
            cat_label = category_mapping.get(base_category)
            if cat_label is None:
                self.log("Invalid category base. Skipping...")
                return

            try:
                status = self.is_active_and_static(seed.ip, seed.port, category=cat, discovered_source_url=discovered_source_url)
            except requests.exceptions.ConnectionError as ce:
                status = f"WINERROR: {ce}"
            if status is None:
                self.log(f"Skipping {seed.ip} due to unavailable HTTP status.")
                return
            if duplicate_flag is None:
                duplicate_flag = (seed.ip in self.visited_ips)

            if status.startswith("WINERROR"):
                if duplicate_flag:
                    comment = f"WINERROR duplicate {seed.source_type} {status}"
                    line = f'{seed.ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                    if cat.startswith("whitelist"):
                        self.write_whitelist_duplicate_line(line)
                    else:
                        self.write_bulk_duplicate_line(line)
                    self.log(f"WinError duplicate output written for {seed.ip}.")
                else:
                    comment = f"WINERROR {seed.source_type} {status}"
                    line = f'{seed.ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                    if cat.startswith("whitelist"):
                        self.write_winerror_whitelist_line(line)
                        self.log(f"WinError whitelist output written for {seed.ip}.")
                    else:
                        self.write_winerror_bulk_line(line)
                        self.log(f"WinError bulk output written for {seed.ip}.")
                return

            elif status.startswith("TIMEOUT"):
                if duplicate_flag:
                    comment = f"TIMEOUT duplicate {seed.source_type} {status}"
                    line = f'{seed.ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                    if cat.startswith("whitelist"):
                        self.write_whitelist_duplicate_line(line)
                    else:
                        self.write_bulk_duplicate_line(line)
                    self.log(f"Timeout duplicate output written for {seed.ip}.")
                else:
                    comment = f"TIMEOUT {seed.source_type} {status}"
                    line = f'{seed.ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                    if cat.startswith("whitelist"):
                        self.write_winerror_whitelist_line(line)
                        self.log(f"Timeout whitelist output written for {seed.ip}.")
                    else:
                        self.write_winerror_bulk_line(line)
                        self.log(f"Timeout bulk output written for {seed.ip}.")
                return

            elif status.startswith("potentially up"):
                seed_verdict = {
                    "whitelist": "whitelist (auto verdict 7)",
                    "phishing": "phishing (auto verdict 8)",
                    "spam": "spam (auto verdict 9)",
                    "ddos": "ddos (auto verdict 10)",
                    "bruteforce": "bruteforce (auto verdict 11)",
                    "malicious": "malicious (auto verdict 12)"
                }.get(base_category, seed.source_type)
                if duplicate_flag:
                    comment = self.comment_template_nozeroday.format(
                        ip=seed.ip,
                        discovered_url=discovered_source_url,
                        verdict=seed_verdict,
                        status=status
                    )
                else:
                    comment = self.comment_template_zeroday.format(
                        ip=seed.ip,
                        discovered_url=discovered_source_url,
                        verdict=seed_verdict,
                        status=status
                    )
                line = f'{seed.ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                if duplicate_flag:
                    if cat.startswith("whitelist"):
                        self.write_whitelist_duplicate_line(line)
                    else:
                        self.write_bulk_duplicate_line(line)
                    self.log(f"Potentially Up duplicate output written for {seed.ip} with status {status}.")
                else:
                    if cat.startswith("whitelist"):
                        self.write_potentially_up_whitelist_line(line)
                        self.log(f"Potentially Up (whitelist) output written for {seed.ip} with status {status}.")
                    else:
                        self.write_potentially_up_bulk_line(line)
                        self.log(f"Potentially Up (bulk) output written for {seed.ip} with status {status}.")
                return

            elif status.startswith("potentially down"):
                if duplicate_flag:
                    comment = f"Potentially down duplicate: {status}"
                    line = f'{seed.ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                    if cat.startswith("whitelist"):
                        self.write_whitelist_duplicate_line(line)
                    else:
                        self.write_bulk_duplicate_line(line)
                    self.log(f"Potentially Down duplicate output written for {seed.ip} with status {status}.")
                else:
                    comment = f"Potentially down: {status}"
                    line = f'{seed.ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                    if cat.startswith("whitelist"):
                        self.write_potentially_down_whitelist_line(line)
                        self.log(f"Potentially Down (whitelist) output written for {seed.ip} with status {status}.")
                    else:
                        self.write_potentially_down_bulk_line(line)
                        self.log(f"Potentially Down (bulk) output written for {seed.ip} with status {status}.")
                return

            elif status.startswith("up:"):
                auto_verdict_mapping_confirmed = {
                    "whitelist": "whitelist (auto verdict 1)",
                    "phishing": "phishing (auto verdict 2)",
                    "spam": "spam (auto verdict 3)",
                    "ddos": "ddos (auto verdict 4)",
                    "bruteforce": "bruteforce (auto verdict 5)",
                    "malicious": "malicious (auto verdict 6)"
                }
                seed_verdict = auto_verdict_mapping_confirmed.get(base_category, seed.source_type)
                similarity_str = ""
                if discovered_source_url:
                    new_url = seed.get_url()
                    if new_url != discovered_source_url:
                        new_content = self.fetch_content(new_url)
                        ref_content = self.fetch_content(discovered_source_url)
                        if new_content and ref_content:
                            similarity = compute_content_similarity(ref_content, new_content)
                            similarity_str = f" HTML similarity: {similarity:.2f}%"
                    else:
                        similarity_str = ""
                if duplicate_flag:
                    comment = self.comment_template_nozeroday.format(
                        ip=seed.ip,
                        discovered_url=discovered_source_url,
                        verdict=seed_verdict,
                        status=status
                    )
                else:
                    comment = self.comment_template_zeroday_up.format(
                        ip=seed.ip,
                        discovered_url=discovered_source_url,
                        verdict=seed_verdict,
                        status=status,
                        similarity=similarity_str
                    )
                line = f'{seed.ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                if duplicate_flag:
                    if cat.startswith("whitelist"):
                        self.write_whitelist_duplicate_line(line)
                    else:
                        self.write_bulk_duplicate_line(line)
                    self.log(f"Duplicate output written for {seed.ip} with status {status}.")
                else:
                    if cat.startswith("whitelist"):
                        self.write_whitelist_line(line)
                        self.log(f"Whitelist output written for {seed.ip}.")
                    else:
                        self.write_bulk_line(line)
                        self.log(f"Bulk output written for {seed.ip}.")
                return
        finally:
            with self.lock:
                self.processed_count += 1
                if self.progress_bar:
                    self.progress_bar.update(1)

    def fetch_content(self, url):
        try:
            response = requests.get(url, timeout=self.request_timeout, allow_redirects=True)
            return response.text
        except Exception as e:
            self.log(f"Error fetching content from {url}: {e}")
            return ""

    def seed_consumer(self):
        while not self.cancelled:
            try:
                seed = self.seed_queue.get(timeout=3)
            except queue.Empty:
                break
            self.process_seed(seed)
            self.seed_queue.task_done()

    def run_scan(self):
        self.log("Loading definitions...")
        self.my_public_ip = self.get_my_public_ip()
        seeds = self.load_seeds()
        if not seeds:
            self.log("No seed IP addresses found.")
            return
        total_seeds = len(seeds)
        self.log(f"Starting with {total_seeds} initial seeds.")
        self.open_csv_files()
        # Populate the seed queue
        for seed in seeds:
            self.seed_queue.put(seed)
        # Set up tqdm progress bar
        self.progress_bar = tqdm(total=total_seeds, desc="Processing seeds", unit="seed")
        # Start consumer threads
        num_consumers = 10
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_consumers) as executor:
            futures = [executor.submit(self.seed_consumer) for _ in range(num_consumers)]
            # Wait until the queue is empty
            self.seed_queue.join()
        self.close_csv_files()
        self.progress_bar.close()
        self.log("Scan completed.")

# -----------------------------
# Main entry point (CLI version)
# -----------------------------
def main():
    worker = ScannerWorker(SETTINGS)
    start_time = time.time()
    worker.run_scan()
    elapsed = time.time() - start_time
    print(f"Scan completed in {time.strftime('%H:%M:%S', time.gmtime(elapsed))}")

if __name__ == "__main__":
    main()

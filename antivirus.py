#!/usr/bin/env python3
import os
import re
import sys
import json
import ipaddress
import threading
import queue
import time
import difflib
import requests
import logging
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from tqdm import tqdm

# Custom warning handler
def custom_warning_handler(message, category, filename, lineno, file=None, line=None):
    logging.warning(f"Warning in {filename}:{lineno}: {category.__name__}: {message}")
warnings.showwarning = custom_warning_handler

# -----------------------------------------------------------------------------
# Directories and File Settings
# -----------------------------------------------------------------------------
script_dir = os.getcwd()
output_dir = os.path.join(script_dir, "output")
log_dir = os.path.join(script_dir, "log")
os.makedirs(output_dir, exist_ok=True)
os.makedirs(log_dir, exist_ok=True)

log_file = os.path.join(log_dir, "antivirus.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    filename=log_file,
    filemode="a"
)

# -----------------------------------------------------------------------------
# Default Settings
# -----------------------------------------------------------------------------
default_bulk = os.path.join(output_dir, "BulkReport.csv")
default_whitelist = os.path.join(output_dir, "WhitelistReport.csv")
DEFAULT_SETTINGS = {
    "MaxThreads": 1000,
    "MaxIPs": 0,  # 0 means unlimited
    "CsvMaxLines": 10000,
    "CsvMaxSize": 2097152,
    "CommentTemplateZeroday": "Related with IP detected by heuristics (Discovered IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict}, HTTP Status: {status}), Zeroday: Yes it's not duplicate",
    "CommentTemplateNoZeroday": "Related with IP detected by heuristics (Discovered IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict}, HTTP Status: {status}), Zeroday: No it's duplicate",
    "CommentTemplateZerodayStatus200": "Related with IP detected by heuristics (Discovered IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict}, HTTP Status: {status}), HTML similarity: {similarity:.2f}%, Zeroday: Yes it's not duplicate",
    "RequestTimeout": 10,
    "BulkOutputFile": default_bulk,
    "WhiteListOutputFile": default_whitelist,
    "PotentiallyUpBulkOutputFile": os.path.join(output_dir, "potentially_up_bulk.csv"),
    "PotentiallyDownBulkOutputFile": os.path.join(output_dir, "potentially_down_bulk.csv"),
    "PotentiallyUpWhiteListOutputFile": os.path.join(output_dir, "potentially_up_whitelist.csv"),
    "PotentiallyDownWhiteListOutputFile": os.path.join(output_dir, "potentially_down_whitelist.csv"),
    "WinErrorBulkOutputFile": os.path.join(output_dir, "winerror_bulk.csv"),
    "WinErrorWhitelistOutputFile": os.path.join(output_dir, "winerror_whitelist.csv"),
    "BulkDuplicateOutputFile": os.path.join(output_dir, "BulkReport_duplicate.csv"),
    "WhiteListDuplicateOutputFile": os.path.join(output_dir, "WhitelistReport_duplicate.csv"),
    "PotentiallyUpBulkDuplicateOutputFile": os.path.join(output_dir, "potentially_up_bulk_duplicate.csv"),
    "PotentiallyDownBulkDuplicateOutputFile": os.path.join(output_dir, "potentially_down_bulk_duplicate.csv"),
    "PotentiallyUpWhiteListDuplicateOutputFile": os.path.join(output_dir, "potentially_up_whitelist_duplicate.csv"),
    "PotentiallyDownWhiteListDuplicateOutputFile": os.path.join(output_dir, "potentially_down_whitelist_duplicate.csv"),
    "WinErrorBulkDuplicateOutputFile": os.path.join(output_dir, "winerror_bulk_duplicate.csv"),
    "WinErrorWhitelistDuplicateOutputFile": os.path.join(output_dir, "winerror_whitelist_duplicate.csv"),
    "ZeroDayExecutableDetection": "true",
    "ZeroDayExecutableOutputFile": os.path.join(output_dir, "ZeroDayExecutables.csv"),
    "ZeroDayExecutableDuplicateOutputFile": os.path.join(output_dir, "ZeroDayExecutables_duplicate.csv"),
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
    "MalwareFilesIPv4": "website/IPv4Malware.txt"
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
            logging.error("Error reading settings: %s", e)
    else:
        logging.info("Settings file not found, using default settings")
    return DEFAULT_SETTINGS

SETTINGS = load_settings_from_file()

# -----------------------------------------------------------------------------
# CSV File Rotation Class (thread-safe)
# -----------------------------------------------------------------------------
class CSVFile:
    def __init__(self, base_path, max_lines, max_size, header="IP,Categories,ReportDate,Comment\n"):
        self.base_path = base_path
        self.max_lines = max_lines
        self.max_size = max_size
        self.header = header
        self.line_count = 1  # header counts as 1 line
        self.size = len(header.encode("utf-8"))
        self.index = 0
        self.open_file()
        self.lock = threading.Lock()
        
    def open_file(self):
        if self.index == 0:
            path = self.base_path
        else:
            base, ext = os.path.splitext(self.base_path)
            path = f"{base}_{self.index}{ext}"
        self.file = open(path, "w", encoding="utf-8")
        self.file.write(self.header)
        self.file.flush()
        
    def write_line(self, line):
        with self.lock:
            line_bytes = len(line.encode("utf-8"))
            if self.line_count >= self.max_lines or (self.size + line_bytes) >= self.max_size:
                self.file.close()
                self.index += 1
                self.line_count = 1
                self.size = len(self.header.encode("utf-8"))
                self.open_file()
            self.file.write(line)
            self.file.flush()
            self.line_count += 1
            self.size += line_bytes
            
    def close(self):
        with self.lock:
            self.file.close()

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------
def compute_similarity(text1, text2):
    return difflib.SequenceMatcher(None, text1, text2).ratio() * 100

def is_valid_ip(ip_string):
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
            return None
        return "ipv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "ipv6"
    except ValueError:
        return None

def extract_ip_and_port(text):
    found_ips = []
    ipv4_pattern = re.compile(r'\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?::(?P<port>\d{1,5}))?\b')
    ipv6_bracket_pattern = re.compile(r'\[(?P<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})\](?::(?P<port>\d{1,5}))?')
    ipv6_pattern = re.compile(r'\b(?P<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})\b')
    for match in ipv6_bracket_pattern.finditer(text):
        ip = match.group('ip')
        port_str = match.group('port')
        port = int(port_str) if port_str and port_str.isdigit() and 1 <= int(port_str) <= 65535 else None
        if is_valid_ip(ip):
            found_ips.append((ip, port, "ipv6"))
    for match in ipv4_pattern.finditer(text):
        ip = match.group('ip')
        port_str = match.group('port')
        if port_str:
            try:
                port = int(port_str)
                if not (1 <= port <= 65535):
                    continue
            except ValueError:
                continue
        else:
            port = None
        if is_valid_ip(ip):
            found_ips.append((ip, port, "ipv4"))
    for match in ipv6_pattern.finditer(text):
        ip = match.group('ip')
        if any(existing[0] == ip for existing in found_ips):
            continue
        if is_valid_ip(ip):
            found_ips.append((ip, None, "ipv6"))
    return found_ips

def load_lines(path, expected_version):
    entries = []
    invalid_entries = []
    paths = [p.strip() for p in path.split(",") if p.strip()]
    for single_path in paths:
        if not os.path.exists(single_path):
            logging.warning("File not found: %s", single_path)
            continue
        with open(single_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue  # Skip empty lines
                parts = line.split(',')
                first_part = parts[0].strip()
                found_ips = extract_ip_and_port(first_part)
                valid = False
                for ip, port, version in found_ips:
                    if version == expected_version and is_valid_ip(ip) == expected_version:
                        entries.append(ip)
                        valid = True
                        break  # At least one valid IP found
                if not valid:
                    invalid_entries.append(line)
        # Write invalid entries for the current file
        if invalid_entries:
            invalid_filename = os.path.join(output_dir, f"invalid_{expected_version}.txt")
            with open(invalid_filename, "a", encoding="utf-8") as invalid_file:
                for invalid_line in invalid_entries:
                    invalid_file.write(f"{invalid_line}\n")
            logging.info("Wrote %d invalid entries from %s to %s", len(invalid_entries), single_path, invalid_filename)
            invalid_entries.clear()  # Clear for next file
    return entries

def load_seeds(settings):
    seeds = []
    seen = set()

    # Define file entries with their respective categories and expected IP versions
    file_entries = [
        (settings["WhiteListFilesIPv4"], "whitelist", "ipv4"),
        (settings["WhiteListFilesIPv6"], "whitelist", "ipv6"),
        (settings["PhishingFilesIPv4Active"], "phishing", "ipv4"),
        (settings["PhishingFilesIPv4InActive"], "phishing", "ipv4"),
        (settings["DDoSFilesIPv4"], "ddos", "ipv4"),
        (settings["DDoSFilesIPv6"], "ddos", "ipv6"),
        (settings["BruteForceFilesIPv4"], "bruteforce", "ipv4"),
        (settings["BruteForceFilesIPv6"], "bruteforce", "ipv6"),
        (settings["SpamFilesIPv4"], "spam", "ipv4"),
        (settings["SpamFilesIPv6"], "spam", "ipv6"),
        (settings["MalwareFilesIPv4"], "malicious", "ipv4"),
        (settings["MalwareFilesIPv6"], "malicious", "ipv6"),
    ]

    for file_paths, category, expected_version in file_entries:
        ips = load_lines(file_paths, expected_version)
        for ip in ips:
            if ip not in seen:
                seeds.append({
                    "ip": ip,
                    "category": category,
                    "version": expected_version,
                    "discovered_url": f"http://{ip}"
                })
                seen.add(ip)
    logging.info("Total seeds loaded: %d", len(seeds))
    return seeds

CATEGORY_MAP = {
    "whitelist": "",
    "phishing": SETTINGS["CategoryPhishing"],
    "ddos": SETTINGS["CategoryDDoS"],
    "bruteforce": SETTINGS["CategoryBruteForce"],
    "spam": SETTINGS["CategorySpam"],
    "malicious": SETTINGS["CategoryMalicious"]
}

def get_my_public_ip(timeout):
    try:
        response = requests.get("https://api.ipify.org", timeout=timeout)
        ip = response.text.strip()
        logging.info("My public IP is %s", ip)
        return ip
    except Exception as e:
        logging.error("Error obtaining public IP: %s", e)
        return None

def is_active_and_static(ip, port, timeout):
    url = f"http://{ip}" + (f":{port}" if port else "")
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        if response.status_code not in [200]:
            return False
        parsed = urlparse(response.url)
        final_ip = parsed.hostname
        final_port = parsed.port if parsed.port else 80
        expected_port = port if port else 80
        return final_ip == ip and final_port == expected_port
    except Exception as e:
        logging.error("Active check failed for %s: %s", url, e)
        return False

processed_results = {}
MY_PUBLIC_IP = None

class ScannerWorker:
    def __init__(self, settings):
        self.settings = settings
        self.timeout = int(settings["RequestTimeout"])
        self.max_ips = int(settings.get("MaxIPs", 0))
        self.seed_queue = queue.Queue()
        self.lock = threading.Lock()
        self.pbar = None
        max_lines = int(settings["CsvMaxLines"])
        max_size = int(settings["CsvMaxSize"])
        header = "IP,Categories,ReportDate,Comment\n"
        
        self.bulk_csv = CSVFile(settings["BulkOutputFile"], max_lines, max_size, header)
        self.whitelist_csv = CSVFile(settings["WhiteListOutputFile"], max_lines, max_size, header)
        self.potentially_up_bulk_csv = CSVFile(settings["PotentiallyUpBulkOutputFile"], max_lines, max_size, header)
        self.potentially_down_bulk_csv = CSVFile(settings["PotentiallyDownBulkOutputFile"], max_lines, max_size, header)
        self.potentially_up_whitelist_csv = CSVFile(settings["PotentiallyUpWhiteListOutputFile"], max_lines, max_size, header)
        self.potentially_down_whitelist_csv = CSVFile(settings["PotentiallyDownWhiteListOutputFile"], max_lines, max_size, header)
        self.winerror_bulk_csv = CSVFile(settings["WinErrorBulkOutputFile"], max_lines, max_size, header)
        self.winerror_whitelist_csv = CSVFile(settings["WinErrorWhitelistOutputFile"], max_lines, max_size, header)
        
        self.bulk_duplicate_csv = CSVFile(settings["BulkDuplicateOutputFile"], max_lines, max_size, header)
        self.whitelist_duplicate_csv = CSVFile(settings["WhiteListDuplicateOutputFile"], max_lines, max_size, header)
        self.potentially_up_bulk_duplicate_csv = CSVFile(settings["PotentiallyUpBulkDuplicateOutputFile"], max_lines, max_size, header)
        self.potentially_down_bulk_duplicate_csv = CSVFile(settings["PotentiallyDownBulkDuplicateOutputFile"], max_lines, max_size, header)
        self.potentially_up_whitelist_duplicate_csv = CSVFile(settings["PotentiallyUpWhiteListDuplicateOutputFile"], max_lines, max_size, header)
        self.potentially_down_whitelist_duplicate_csv = CSVFile(settings["PotentiallyDownWhiteListDuplicateOutputFile"], max_lines, max_size, header)
        self.winerror_bulk_duplicate_csv = CSVFile(settings["WinErrorBulkDuplicateOutputFile"], max_lines, max_size, header)
        self.winerror_whitelist_duplicate_csv = CSVFile(settings["WinErrorWhitelistDuplicateOutputFile"], max_lines, max_size, header)
        
        if settings["ZeroDayExecutableDetection"].lower() == "true":
            self.zeroday_csv = CSVFile(settings["ZeroDayExecutableOutputFile"], max_lines, max_size, header)
            self.zeroday_duplicate_csv = CSVFile(settings["ZeroDayExecutableDuplicateOutputFile"], max_lines, max_size, header)
        else:
            self.zeroday_csv = None
            self.zeroday_duplicate_csv = None

    def close_files(self):
        regular_files = [
            self.bulk_csv, self.whitelist_csv, 
            self.potentially_up_bulk_csv, self.potentially_down_bulk_csv,
            self.potentially_up_whitelist_csv, self.potentially_down_whitelist_csv,
            self.winerror_bulk_csv, self.winerror_whitelist_csv
        ]
        duplicate_files = [
            self.bulk_duplicate_csv, self.whitelist_duplicate_csv,
            self.potentially_up_bulk_duplicate_csv, self.potentially_down_bulk_duplicate_csv,
            self.potentially_up_whitelist_duplicate_csv, self.potentially_down_whitelist_duplicate_csv,
            self.winerror_bulk_duplicate_csv, self.winerror_whitelist_duplicate_csv
        ]
        for csv_obj in regular_files + duplicate_files:
            csv_obj.close()
        if self.zeroday_csv:
            self.zeroday_csv.close()
        if self.zeroday_duplicate_csv:
            self.zeroday_duplicate_csv.close()

    def final_write(self):
        report_date = datetime.now(timezone.utc).isoformat()
        for ip, data in processed_results.items():
            all_categories = '"' + ",".join(sorted(data["categories"])) + '"'
            comment = data.get("last_comment", "").strip()
            is_duplicate = data.get("is_initial", False) or data.get("count", 0) > 1
            status_type = data.get("status_type", "up")
            is_whitelist = "whitelist" in data["categories"]
            
            if is_duplicate:
                if is_whitelist:
                    if status_type == "potentially_up":
                        self.potentially_up_whitelist_duplicate_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                    elif status_type == "potentially_down":
                        self.potentially_down_whitelist_duplicate_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                    elif status_type == "winerror":
                        self.winerror_whitelist_duplicate_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                    else:
                        self.whitelist_duplicate_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                else:
                    if status_type == "potentially_up":
                        self.potentially_up_bulk_duplicate_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                    elif status_type == "potentially_down":
                        self.potentially_down_bulk_duplicate_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                    elif status_type == "winerror":
                        self.winerror_bulk_duplicate_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                    else:
                        self.bulk_duplicate_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
            else:
                if is_whitelist:
                    if status_type == "potentially_up":
                        self.potentially_up_whitelist_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                    elif status_type == "potentially_down":
                        self.potentially_down_whitelist_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                    elif status_type == "winerror":
                        self.winerror_whitelist_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                    else:
                        self.whitelist_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                else:
                    if status_type == "potentially_up":
                        self.potentially_up_bulk_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                    elif status_type == "potentially_down":
                        self.potentially_down_bulk_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                    elif status_type == "winerror":
                        self.winerror_bulk_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
                    else:
                        self.bulk_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')

    def process_seed(self, ip, category, version, discovered_url, initial_ip=False):
        with self.lock:
            if ip not in processed_results:
                processed_results[ip] = {
                    "categories": set(),
                    "last_comment": "",
                    "is_initial": False,
                    "count": 0,
                    "processed": False,
                    "status_type": "up"
                }
            if initial_ip:
                processed_results[ip]["is_initial"] = True
            processed_results[ip]["categories"].add(category)
            processed_results[ip]["count"] += 1
            already_processed = processed_results[ip]["processed"]
        
        if already_processed:
            return

        with self.lock:
            processed_results[ip]["processed"] = True

        port = None
        base_url = f"http://{ip}"
        base_content = None  # Track base content for similarity checks
        visited = set()
        to_process = set([base_url])

        def process_page(url):
            nonlocal base_content
            new_sub_urls = set()
            try:
                response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            except requests.exceptions.ConnectionError as ce:
                with self.lock:
                    processed_results[ip]["status_type"] = "winerror"
                    processed_results[ip]["last_comment"] = self.settings["CommentTemplateNoZeroday"].format(
                        ip=ip, discovered_url=discovered_url, verdict=category, status="Connection Error"
                    )
                return new_sub_urls
            except Exception as e:
                with self.lock:
                    processed_results[ip]["status_type"] = "winerror"
                    processed_results[ip]["last_comment"] = self.settings["CommentTemplateNoZeroday"].format(
                        ip=ip, discovered_url=discovered_url, verdict=category, status=str(e)
                    )
                return new_sub_urls

            # --- ZeroDay Executable Check ---
            if response.status_code == 200:
                header_bytes = response.content[:4]
                if header_bytes.startswith((b'MZ', b'\x7FELF')):
                    signature = "MZ" if header_bytes.startswith(b'MZ') else "ELF"
                    comment = f"ZeroDay Executable detected ({signature} signature)"
                    with self.lock:
                        processed_results[ip]["categories"].add("malicious")
                        processed_results[ip]["last_comment"] = comment
                        processed_results[ip]["status_type"] = "up"
                    return new_sub_urls  # Skip further processing

        code_str = f"{response.status_code:03d}"
        up_codes = set(self.settings["HTTPUpCodes"].split(","))
        potentially_up_codes = set(self.settings["HTTPPotentiallyUpCodes"].split(","))
        potentially_down_codes = set(self.settings["HTTPPotentiallyDownCodes"].split(","))

        base_content = None

        if url == base_url and response.status_code == 200:
            base_content = response.text

        similarity = 0.0
        final_comment = ""
        status_type = "up"

        # Check for ZeroDay Executable
        if response.status_code == 200:
            header_bytes = response.content[:4]
            if header_bytes.startswith(b'MZ'):
                final_comment = "ZeroDay Executable detected (MZ signature)"
                with self.lock:
                    processed_results[ip]["categories"].add("malicious")
                    processed_results[ip]["last_comment"] = final_comment
                    processed_results[ip]["status_type"] = "up"
            elif header_bytes.startswith(b'\x7FELF'):
                final_comment = "ZeroDay Executable detected (ELF signature)"
                with self.lock:
                    processed_results[ip]["categories"].add("malicious")
                    processed_results[ip]["last_comment"] = final_comment
                    processed_results[ip]["status_type"] = "up"
            else:
                # Proceed with similarity check if not an executable
                if base_content and url != base_url:
                    similarity = compute_similarity(response.text, base_content)

        # If executable was detected, skip other comment templates
        if not final_comment:
            if code_str in up_codes:
                if response.status_code == 200:
                    final_comment = self.settings["CommentTemplateZerodayStatus200"].format(
                        ip=ip, discovered_url=discovered_url, verdict=category, status=code_str, similarity=similarity
                    )
                else:
                    final_comment = self.settings["CommentTemplateZeroday"].format(
                        ip=ip, discovered_url=discovered_url, verdict=category, status=code_str
                    )
                status_type = "up"
            elif code_str in potentially_up_codes:
                final_comment = self.settings["CommentTemplateNoZeroday"].format(
                    ip=ip, discovered_url=discovered_url, verdict=category, status=code_str
                )
                status_type = "potentially_up"
            elif code_str in potentially_down_codes:
                final_comment = self.settings["CommentTemplateNoZeroday"].format(
                    ip=ip, discovered_url=discovered_url, verdict=category, status=code_str
                )
                status_type = "potentially_down"
            else:
                final_comment = self.settings["CommentTemplateNoZeroday"].format(
                    ip=ip, discovered_url=discovered_url, verdict=category, status=code_str
                )
                status_type = "up"

        with self.lock:
            if not processed_results[ip]["last_comment"]:  # Only update if not already set by executable check
                processed_results[ip]["last_comment"] = final_comment
                processed_results[ip]["status_type"] = status_type

            try:
                with warnings.catch_warnings():
                    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
                    soup = BeautifulSoup(response.text, "lxml")
            except Exception as e:
                logging.error("lxml parser failed for %s: %s", url, e)
                try:
                    soup = BeautifulSoup(response.text, "html.parser")
                except Exception as e:
                    logging.error("html.parser failed for %s: %s", url, e)
                    return new_sub_urls, None

            if response.status_code == 200:
                for tag in soup.find_all(["script", "link", "img"]):
                    attr = "src" if tag.name in ["script", "img"] else "href"
                    url_val = tag.get(attr)
                    if url_val:
                        full_url = urljoin(url, url_val)
                        parsed = urlparse(full_url)
                        if parsed.hostname == ip:
                            if full_url not in visited:
                                new_sub_urls.add(full_url)
                        else:
                            new_ips = extract_ip_and_port(full_url)
                            for new_ip, new_port, new_version in new_ips:
                                if new_ip != ip:
                                    with self.lock:
                                        if self.max_ips > 0 and len(processed_results) >= self.max_ips:
                                            continue
                                        if new_ip not in processed_results:
                                            new_seed = {
                                                "ip": new_ip,
                                                "category": category,
                                                "version": new_version,
                                                "discovered_url": full_url
                                            }
                                            self.seed_queue.put(new_seed)
                                            if self.pbar:
                                                self.pbar.total += 1
                                                self.pbar.refresh()

                content_text = response.text
                if content_text:
                    content_ips = extract_ip_and_port(content_text)
                    for new_ip, new_port, new_version in content_ips:
                        if new_ip != ip:
                            with self.lock:
                                if self.max_ips > 0 and len(processed_results) >= self.max_ips:
                                    continue
                                if new_ip not in processed_results:
                                    new_seed = {
                                        "ip": new_ip,
                                        "category": "malicious",
                                        "version": new_version,
                                        "discovered_url": url
                                    }
                                    self.seed_queue.put(new_seed)
                                    if self.pbar:
                                        self.pbar.total += 1
                                        self.pbar.refresh()

            return new_sub_urls, response.text

        # --- Main URL Processing Loop ---
        while to_process:
            current_url = to_process.pop()
            if current_url in visited:
                continue
            visited.add(current_url)

            new_urls = process_page(current_url)
            to_process.update(new_urls - visited)

    def worker(self):
        while True:
            try:
                seed = self.seed_queue.get(timeout=5)
            except queue.Empty:
                break
            
            with self.lock:
                if self.max_ips > 0 and len(processed_results) >= self.max_ips:
                    self.seed_queue.task_done()
                    break
            
            self.process_seed(
                seed["ip"],
                seed["category"],
                seed["version"],
                seed["discovered_url"],
                initial_ip=seed.get("initial", False)
            )
            self.seed_queue.task_done()
            
            with self.lock:
                if self.pbar:
                    self.pbar.update(1)

    def run(self, seeds):
        global MY_PUBLIC_IP
        MY_PUBLIC_IP = get_my_public_ip(self.timeout)
        
        for seed in seeds:
            with self.lock:
                if seed["ip"] not in processed_results:
                    processed_results[seed["ip"]] = {
                        "categories": set(),
                        "last_comment": "",
                        "is_initial": True,
                        "count": 0,
                        "processed": False,
                        "status_type": "up"
                    }
                processed_results[seed["ip"]]["categories"].add(seed["category"])
                processed_results[seed["ip"]]["count"] += 1
            seed["initial"] = True
            self.seed_queue.put(seed)
        
        initial_total = self.seed_queue.qsize()
        self.pbar = tqdm(total=initial_total, desc="Processing seeds")
        
        threads = []
        max_threads = min(int(self.settings["MaxThreads"]), initial_total)
        for _ in range(max_threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
        
        self.seed_queue.join()
        
        for t in threads:
            t.join()
        
        self.pbar.close()
        
        self.final_write()
        self.close_files()
        logging.info("Scan completed.")

def main():
    seeds = load_seeds(SETTINGS)
    if not seeds:
        logging.error("No seeds loaded. Exiting.")
        sys.exit(1)
    worker = ScannerWorker(SETTINGS)
    start_time = time.time()
    worker.run(seeds)
    elapsed = time.time() - start_time
    print("Scan completed in", time.strftime('%H:%M:%S', time.gmtime(elapsed)))

if __name__ == "__main__":
    main()
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
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from tqdm import tqdm

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
# Default Settings (All properties integrated)
# -----------------------------------------------------------------------------
default_bulk = os.path.join(output_dir, "BulkReport.csv")
default_whitelist = os.path.join(output_dir, "WhitelistReport.csv")
DEFAULT_SETTINGS = {
    "MaxThreads": 1000,
    "CsvMaxLines": 10000,
    "CsvMaxSize": 2097152,
    "CommentTemplateZeroday": "Related with IP detected by heuristics (Discovered IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict}, HTTP Status: {status}), Zeroday: Yes it's not duplicate",
    "CommentTemplateNoZeroday": "Related with IP detected by heuristics (Discovered IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict}, HTTP Status: {status}), Zeroday: No it's duplicate",
    # Renamed template for HTTP 200 responses with similarity check.
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
# CSV File Rotation Class
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

def load_lines(path):
    entries = []
    paths = [p.strip() for p in path.split(",") if p.strip()]
    for single_path in paths:
        if os.path.exists(single_path):
            with open(single_path, "r", encoding="utf-8") as f:
                for line in f:
                    ip = line.strip().split(",")[0].strip().lower()
                    if ip and is_valid_ip(ip):
                        entries.append(ip)
            logging.info("Loaded %d IPs from %s", len(entries), single_path)
    return entries

def load_seeds(settings):
    seeds = []
    file_category_mapping = {
        settings["WhiteListFilesIPv4"]: "whitelist",
        settings["WhiteListFilesIPv6"]: "whitelist",
        settings["PhishingFilesIPv4Active"]: "phishing",
        settings["PhishingFilesIPv4InActive"]: "phishing",
        settings["DDoSFilesIPv4"]: "ddos",
        settings["DDoSFilesIPv6"]: "ddos",
        settings["BruteForceFilesIPv4"]: "bruteforce",
        settings["BruteForceFilesIPv6"]: "bruteforce",
        settings["SpamFilesIPv4"]: "spam",
        settings["SpamFilesIPv6"]: "spam",
        settings["MalwareFilesIPv4"]: "malicious",
        settings["MalwareFilesIPv6"]: "malicious"
    }
    seen = set()
    for file, category in file_category_mapping.items():
        ips = load_lines(file)
        for ip in ips:
            if ip not in seen:
                version = is_valid_ip(ip)
                seeds.append({"ip": ip, "category": category, "version": version})
                seen.add(ip)
    logging.info("Total seeds loaded: %d", len(seeds))
    return seeds

# Category mapping: use settings values for categories
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
        if final_ip and is_valid_ip(final_ip) and final_ip == ip and final_port == expected_port:
            return True
        return False
    except Exception as e:
        logging.error("Active check failed for %s: %s", url, e)
        return False

# -----------------------------------------------------------------------------
# Advanced ScannerWorker with All Features
# -----------------------------------------------------------------------------
class ScannerWorker:
    def __init__(self, settings):
        self.settings = settings
        self.timeout = int(settings["RequestTimeout"])
        self.seed_queue = queue.Queue()
        self.lock = threading.Lock()
        self.pbar = None  # Progress bar for processed IP count
        max_lines = int(settings["CsvMaxLines"])
        max_size = int(settings["CsvMaxSize"])
        header = "IP,Categories,ReportDate,Comment\n"
        # Create CSVFile objects for each output type
        self.bulk_csv = CSVFile(settings["BulkOutputFile"], max_lines, max_size, header)
        self.whitelist_csv = CSVFile(settings["WhiteListOutputFile"], max_lines, max_size, header)
        self.potentially_up_bulk_csv = CSVFile(settings["PotentiallyUpBulkOutputFile"], max_lines, max_size, header)
        self.potentially_down_bulk_csv = CSVFile(settings["PotentiallyDownBulkOutputFile"], max_lines, max_size, header)
        self.potentially_up_whitelist_csv = CSVFile(settings["PotentiallyUpWhiteListOutputFile"], max_lines, max_size, header)
        self.potentially_down_whitelist_csv = CSVFile(settings["PotentiallyDownWhiteListOutputFile"], max_lines, max_size, header)
        self.winerror_bulk_csv = CSVFile(settings["WinErrorBulkOutputFile"], max_lines, max_size, header)
        self.winerror_whitelist_csv = CSVFile(settings["WinErrorWhitelistOutputFile"], max_lines, max_size, header)
        self.bulk_duplicate_csv = CSVFile(settings["BulkDuplicateOutputFile"], max_lines, max_size, header)
        self.whitelist_duplicate_csv = CSVFile(settings["WhitelistDuplicateOutputFile"], max_lines, max_size, header)
        if settings["ZeroDayExecutableDetection"].lower() == "true":
            self.zeroday_csv = CSVFile(settings["ZeroDayExecutableOutputFile"], max_lines, max_size, header)
        else:
            self.zeroday_csv = None

    def close_files(self):
        for csv_obj in [self.bulk_csv, self.whitelist_csv, self.potentially_up_bulk_csv,
                        self.potentially_down_bulk_csv, self.potentially_up_whitelist_csv,
                        self.potentially_down_whitelist_csv, self.winerror_bulk_csv,
                        self.winerror_whitelist_csv, self.bulk_duplicate_csv, self.whitelist_duplicate_csv]:
            csv_obj.close()
        if self.zeroday_csv:
            self.zeroday_csv.close()

    def check_zeroday_executable(self, url, originating_ip):
        try:
            response = requests.get(url, timeout=self.timeout, stream=True)
            if response.status_code == 200:
                header_bytes = response.raw.read(4)
                if header_bytes.startswith(b'MZ'):
                    report_date = datetime.now(timezone.utc).isoformat()
                    comment = "ZeroDay Executable detected (MZ signature)"
                    line = f'{originating_ip},{url},{report_date},"{comment}"\n'
                    with self.lock:
                        self.zeroday_csv.write_line(line)
                    logging.info("ZeroDay executable detected (MZ) at %s", url)
                elif header_bytes == b'\x7FELF':
                    report_date = datetime.now(timezone.utc).isoformat()
                    comment = "ZeroDay Executable detected (ELF signature)"
                    line = f'{originating_ip},{url},{report_date},"{comment}"\n'
                    with self.lock:
                        self.zeroday_csv.write_line(line)
                    logging.info("ZeroDay executable detected (ELF) at %s", url)
        except Exception as e:
            logging.error("Error in ZeroDay executable check for %s: %s", url, e)

    def process_seed(self, seed):
        ip = seed["ip"]
        category = seed["category"]
        version = seed["version"]
        port = None  # Extend if port info is available
        if ip in processed_ips or (MY_PUBLIC_IP and ip == MY_PUBLIC_IP):
            return
        with self.lock:
            processed_ips.add(ip)
        base_url = f"http://{ip}" + (f":{port}" if port else "")
        
        try:
            response = requests.get(base_url, timeout=self.timeout, allow_redirects=True)
        except requests.exceptions.ConnectionError as ce:
            # If connection is refused, check for WinError 10061
            if "10061" in str(ce):
                logging.info("Server is up with firewall detected at %s", base_url)
                cat_label = CATEGORY_MAP.get(category, "")
                comment = "Server is up but connection refused (firewall detected)"
                if category == "whitelist":
                    self.whitelist_csv.write_line(
                        f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                    )
                else:
                    self.bulk_csv.write_line(
                        f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                    )
                return
            else:
                logging.error("Error accessing %s: %s", base_url, ce)
                cat_label = CATEGORY_MAP.get(category, "")
                if category == "whitelist":
                    self.winerror_whitelist_csv.write_line(
                        f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"Connection error: {ce}"\n'
                    )
                else:
                    self.winerror_bulk_csv.write_line(
                        f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"Connection error: {ce}"\n'
                    )
                return
        except Exception as e:
            logging.error("Error accessing %s: %s", base_url, e)
            cat_label = CATEGORY_MAP.get(category, "")
            if category == "whitelist":
                self.winerror_whitelist_csv.write_line(
                    f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"Connection error: {e}"\n'
                )
            else:
                self.winerror_bulk_csv.write_line(
                    f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"Connection error: {e}"\n'
                )
            return

        code_str = f"{response.status_code:03d}"
        up_codes = set(code.strip() for code in self.settings["HTTPUpCodes"].split(","))
        potentially_up_codes = set(code.strip() for code in self.settings["HTTPPotentiallyUpCodes"].split(","))
        potentially_down_codes = set(code.strip() for code in self.settings["HTTPPotentiallyDownCodes"].split(","))
        cat_label = CATEGORY_MAP.get(category, "")

        # Check for up status
        if code_str in up_codes:
            if code_str == "200":
                # Set similarity = 0.0 by default
                similarity = 0.0
                if "source_url" in seed and seed["source_url"]:
                    try:
                        ref_resp = requests.get(seed["source_url"], timeout=self.timeout, allow_redirects=True)
                        similarity = compute_similarity(ref_resp.text, response.text)
                    except Exception:
                        similarity = 0.0
                comment = self.settings["CommentTemplateZerodayStatus200"].format(
                    ip=ip, discovered_url=base_url, verdict=category, status=code_str, similarity=similarity
                )
            else:
                comment = self.settings["CommentTemplateZeroday"].format(
                    ip=ip, discovered_url=base_url, verdict=category, status=code_str
                )
            if category == "whitelist":
                self.whitelist_csv.write_line(
                    f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                )
            else:
                self.bulk_csv.write_line(
                    f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                )
        elif code_str in potentially_up_codes:
            comment = self.settings["CommentTemplateNoZeroday"].format(
                ip=ip, discovered_url=base_url, verdict=category, status=code_str
            )
            if category == "whitelist":
                self.potentially_up_whitelist_csv.write_line(
                    f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                )
            else:
                self.potentially_up_bulk_csv.write_line(
                    f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                )
        elif code_str in potentially_down_codes:
            comment = self.settings["CommentTemplateNoZeroday"].format(
                ip=ip, discovered_url=base_url, verdict=category, status=code_str
            )
            if category == "whitelist":
                self.potentially_down_whitelist_csv.write_line(
                    f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                )
            else:
                self.potentially_down_bulk_csv.write_line(
                    f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                )
        else:
            comment = self.settings["CommentTemplateNoZeroday"].format(
                ip=ip, discovered_url=base_url, verdict=category, status=code_str
            )
            if category == "whitelist":
                self.whitelist_duplicate_csv.write_line(
                    f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                )
            else:
                self.bulk_duplicate_csv.write_line(
                    f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
                )

        # Enqueue additional discovered IPs from the page content
        content = response.text
        new_ips = extract_ip_and_port(content)
        for new_ip, new_port, new_version in new_ips:
            if new_ip not in processed_ips and new_ip != ip:
                new_seed = {"ip": new_ip, "category": category, "version": new_version}
                self.seed_queue.put(new_seed)

        # Advanced: Scan resource URLs from tags and check for zero-day executables
        if response.status_code == 200:
            soup = BeautifulSoup(content, "html.parser")
            resource_urls = set()
            for tag in soup.find_all(["script", "link", "img"]):
                attr = "src" if tag.name in ["script", "img"] else "href"
                url_val = tag.get(attr)
                if url_val:
                    full_url = urljoin(base_url, url_val)
                    resource_urls.add(full_url)
            for resource_url in resource_urls:
                try:
                    res = requests.get(resource_url, timeout=self.timeout, allow_redirects=True)
                    res_code_str = f"{res.status_code:03d}"
                    if self.zeroday_csv and res.status_code == 200:
                        self.check_zeroday_executable(resource_url, ip)
                    if res_code_str in up_codes:
                        resource_ips = extract_ip_and_port(res.text)
                        for extracted_ip, extracted_port, extracted_version in resource_ips:
                            if extracted_ip not in processed_ips and extracted_ip != ip:
                                new_seed = {"ip": extracted_ip, "category": category, "version": extracted_version}
                                self.seed_queue.put(new_seed)
                except Exception as e:
                    logging.error("Error processing resource URL %s: %s", resource_url, e)

    def worker(self):
        while True:
            try:
                seed = self.seed_queue.get(timeout=5)
            except queue.Empty:
                break
            self.process_seed(seed)
            self.seed_queue.task_done()
            # Update progress by 1 for each IP processed
            with self.lock:
                if self.pbar:
                    self.pbar.update(1)

    def run(self, seeds):
        global MY_PUBLIC_IP
        MY_PUBLIC_IP = get_my_public_ip(self.timeout)
        for seed in seeds:
            self.seed_queue.put(seed)
        # Initialize the progress bar with the current number of seeds in the queue.
        initial_total = self.seed_queue.qsize()
        self.pbar = tqdm(total=initial_total, desc="Processing seeds")
        threads = []
        for _ in range(int(self.settings["MaxThreads"])):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
        self.seed_queue.join()
        for t in threads:
            t.join()
        self.pbar.close()
        self.close_files()
        logging.info("Scan completed.")

# Global set to track processed IPs and public IP
processed_ips = set()
MY_PUBLIC_IP = None

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

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

# Define a custom warning handler that logs warnings instead of suppressing them.
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
# Default Settings (All properties integrated)
# -----------------------------------------------------------------------------
default_bulk = os.path.join(output_dir, "BulkReport.csv")
default_whitelist = os.path.join(output_dir, "WhitelistReport.csv")
DEFAULT_SETTINGS = {
    "MaxThreads": 1000,
    "MaxIPs": 0,  # 0 means unlimited; set to a positive integer to limit processed unique IPs.
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
    "WhitelistDuplicateOutputFile": os.path.join(output_dir, "WhitelistReport_duplicate.csv"),
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
# CSV File Rotation Class (with thread-safe write)
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
# Global state: processed results and public IP.
# -----------------------------------------------------------------------------
# processed_results maps ip -> {"categories": set([...]), "last_comment": <str>, "direct_written": <bool>, "processed": <bool>}
processed_results = {}
MY_PUBLIC_IP = None

# -----------------------------------------------------------------------------
# Advanced ScannerWorker with All Features (modified)
# -----------------------------------------------------------------------------
class ScannerWorker:
    def __init__(self, settings):
        self.settings = settings
        self.timeout = int(settings["RequestTimeout"])
        self.max_ips = int(settings.get("MaxIPs", 0))  # 0 means unlimited
        self.seed_queue = queue.Queue()
        self.lock = threading.Lock()
        self.pbar = None  # Progress bar for processed IP count
        max_lines = int(settings["CsvMaxLines"])
        max_size = int(settings["CsvMaxSize"])
        header = "IP,Categories,ReportDate,Comment\n"
        # Final bulk and whitelist CSVs (for aggregated entries)
        self.bulk_csv = CSVFile(settings["BulkOutputFile"], max_lines, max_size, header)
        self.whitelist_csv = CSVFile(settings["WhiteListOutputFile"], max_lines, max_size, header)
        # Other CSV files (errors, duplicates, etc.)
        self.potentially_up_bulk_csv = CSVFile(settings["PotentiallyUpBulkOutputFile"], max_lines, max_size, header)
        self.potentially_down_bulk_csv = CSVFile(settings["PotentiallyDownBulkOutputFile"], max_lines, max_size, header)
        self.potentially_up_whitelist_csv = CSVFile(settings["PotentiallyUpWhiteListOutputFile"], max_lines, max_size, header)
        self.potentially_down_whitelist_csv = CSVFile(settings["PotentiallyDownWhiteListOutputFile"], max_lines, max_size, header)
        self.winerror_bulk_csv = CSVFile(settings["WinErrorBulkOutputFile"], max_lines, max_size, header)
        self.winerror_whitelist_csv = CSVFile(settings["WinErrorWhitelistOutputFile"], max_lines, max_size, header)
        # Duplicate CSV files for both lists (now no longer used, but kept if needed)
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

    def final_write(self):
        """Write aggregated bulk records and whitelist entries that were not directly written."""
        report_date = datetime.now(timezone.utc).isoformat()
        for ip, data in processed_results.items():
            # Skip whitelist IPs that have been written directly
            if "whitelist" in data["categories"] and data.get("direct_written", False):
                continue
            all_categories = '"' + ",".join(sorted(data["categories"])) + '"'
            comment = data.get("last_comment", "Aggregated result")
            if "whitelist" in data["categories"]:
                self.whitelist_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')
            else:
                self.bulk_csv.write_line(f'{ip},{all_categories},{report_date},"{comment}"\n')

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

    # Modified process_seed method: uses an "initial_ip" flag.
    def process_seed(self, ip, category, version, initial_ip=False):
        with self.lock:
            if initial_ip:
                # For initial seeds, we assume they were preloaded.
                processed_results[ip]["categories"].add(category)
            else:
                if ip not in processed_results:
                    processed_results[ip] = {
                        "categories": set(),
                        "last_comment": "",
                        "direct_written": False,
                        "processed": False
                    }
                processed_results[ip]["categories"].add(category)
                # For non-initial seeds, skip processing if already processed.
                if processed_results[ip]["processed"]:
                    return
            # Mark the IP as processed.
            processed_results[ip]["processed"] = True

        port = None  # Extend if port info is available
        base_url = f"http://{ip}" + (f":{port}" if port else "")
        visited = set()
        to_process = set([base_url])

        def process_page(url, visited):
            new_sub_urls = set()
            try:
                response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            except requests.exceptions.ConnectionError as ce:
                with self.lock:
                    cat_label = CATEGORY_MAP.get(category, "")
                    if category == "whitelist":
                        self.winerror_whitelist_csv.write_line(
                            f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"Connection error: {ce}"\n'
                        )
                    else:
                        self.winerror_bulk_csv.write_line(
                            f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"Connection error: {ce}"\n'
                        )
                return new_sub_urls, None
            except Exception as e:
                with self.lock:
                    cat_label = CATEGORY_MAP.get(category, "")
                    if category == "whitelist":
                        self.winerror_whitelist_csv.write_line(
                            f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"Connection error: {e}"\n'
                        )
                    else:
                        self.winerror_bulk_csv.write_line(
                            f'{ip},{cat_label},{datetime.now(timezone.utc).isoformat()},"Connection error: {e}"\n'
                        )
                return new_sub_urls, None

            code_str = f"{response.status_code:03d}"
            up_codes = set(code.strip() for code in self.settings["HTTPUpCodes"].split(","))
            potentially_up_codes = set(code.strip() for code in self.settings["HTTPPotentiallyUpCodes"].split(","))
            potentially_down_codes = set(code.strip() for code in self.settings["HTTPPotentiallyDownCodes"].split(","))
            final_comment = ""
            if code_str in up_codes:
                if code_str == "200":
                    similarity = 0.0
                    final_comment = self.settings["CommentTemplateZerodayStatus200"].format(
                        ip=ip, discovered_url=url, verdict=category, status=code_str, similarity=similarity
                    )
                else:
                    final_comment = self.settings["CommentTemplateZeroday"].format(
                        ip=ip, discovered_url=url, verdict=category, status=code_str
                    )
            elif code_str in potentially_up_codes:
                final_comment = self.settings["CommentTemplateNoZeroday"].format(
                    ip=ip, discovered_url=url, verdict=category, status=code_str
                )
            elif code_str in potentially_down_codes:
                final_comment = self.settings["CommentTemplateNoZeroday"].format(
                    ip=ip, discovered_url=url, verdict=category, status=code_str
                )
            else:
                final_comment = self.settings["CommentTemplateNoZeroday"].format(
                    ip=ip, discovered_url=url, verdict=category, status=code_str
                )
            with self.lock:
                processed_results[ip]["last_comment"] = final_comment

            try:
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
                                            new_seed = {"ip": new_ip, "category": category, "version": new_version}
                                            self.seed_queue.put(new_seed)
                                            self.pbar.total += 1
                                            self.pbar.refresh()
                new_ips_content = extract_ip_and_port(response.text)
                for new_ip, new_port, new_version in new_ips_content:
                    if new_ip != ip:
                        with self.lock:
                            if self.max_ips > 0 and len(processed_results) >= self.max_ips:
                                continue
                            if new_ip not in processed_results:
                                new_seed = {"ip": new_ip, "category": category, "version": new_version}
                                self.seed_queue.put(new_seed)
                                self.pbar.total += 1
                                self.pbar.refresh()
            return new_sub_urls, response.text

        while to_process:
            current_url = to_process.pop()
            visited.add(current_url)
            new_urls, _ = process_page(current_url, visited)
            for url in new_urls:
                if url not in visited:
                    to_process.add(url)

        # If the processed seed is whitelist, write it directly now.
        report_date = datetime.now(timezone.utc).isoformat()
        with self.lock:
            if category == "whitelist":
                self.whitelist_csv.write_line(
                    f'{ip},"{",".join(sorted(processed_results[ip]["categories"]))}",{report_date},"{processed_results[ip]["last_comment"]}"\n'
                )
                processed_results[ip]["direct_written"] = True

    # Modified worker method to always call process_seed with initial_ip=True for initial seeds.
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
            self.process_seed(seed["ip"], seed["category"], seed["version"], initial_ip=seed.get("initial", False))
            self.seed_queue.task_done()
            with self.lock:
                if self.pbar:
                    self.pbar.update(1)

    def run(self, seeds):
        global MY_PUBLIC_IP
        MY_PUBLIC_IP = get_my_public_ip(self.timeout)
        # Pre-populate processed_results with all initial seeds.
        for seed in seeds:
            with self.lock:
                processed_results.setdefault(seed["ip"], {"categories": set(), "last_comment": "", "direct_written": False, "processed": False})
                processed_results[seed["ip"]]["categories"].add(seed["category"])
            # Mark these as initial by setting a flag in the seed dictionary.
            seed["initial"] = True
            self.seed_queue.put(seed)
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

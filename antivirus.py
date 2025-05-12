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
    "PhishingFilesIPv4Active": "website/IPv4PhishingActive.txt",
    "PhishingFilesIPv4InActive": "website/IPv4PhishingInActive.txt",
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
    seen_paths = set()
    # 3. Move invalid_entries per file for immediate write
    for raw in path.split(","):
        single_path = raw.strip()
        if not single_path or single_path in seen_paths:
            continue
        seen_paths.add(single_path)
        if not os.path.exists(single_path):
            logging.warning("File not found: %s", single_path)
            continue

        invalid_entries = []
        with open(single_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # extract the first CSV field
                first_part = line.split(',')[0].strip()
                found_ips = extract_ip_and_port(first_part)
                valid = False
                for ip, port, version in found_ips:
                    if version == expected_version:
                        entries.append(ip)
                        valid = True
                        break
                if not valid:
                    invalid_entries.append(line)

        if invalid_entries:
            invalid_filename = os.path.join(output_dir, f"invalid_{expected_version}.txt")
            with open(invalid_filename, "a", encoding="utf-8") as inv_f:
                for iv in invalid_entries:
                    inv_f.write(iv + "\n")
            logging.info("Wrote %d invalid entries from %s to %s", len(invalid_entries), single_path, invalid_filename)
    return entries

# Load initial seeds
def load_seeds(settings):
    mapping = [
        (settings['WhiteListFilesIPv4'],   'whitelist', 'ipv4'),
        (settings['WhiteListFilesIPv6'],   'whitelist', 'ipv6'),
        (settings['PhishingFilesIPv4Active'],'phishing','ipv4'),
        (settings['PhishingFilesIPv4InActive'],'phishing','ipv4'),
        (settings['DDoSFilesIPv4'],        'ddos',      'ipv4'),
        (settings['DDoSFilesIPv6'],        'ddos',      'ipv6'),
        (settings['BruteForceFilesIPv4'],  'bruteforce','ipv4'),
        (settings['BruteForceFilesIPv6'],  'bruteforce','ipv6'),
        (settings['SpamFilesIPv4'],        'spam',      'ipv4'),
        (settings['SpamFilesIPv6'],        'spam',      'ipv6'),
        (settings['MalwareFilesIPv4'],     'malicious', 'ipv4'),
        (settings['MalwareFilesIPv6'],     'malicious', 'ipv6')
    ]
    seeds, seen = [], set()
    for paths,cat,ver in mapping:
        for ip in load_lines(paths, ver):
            if ip not in seen:
                seeds.append({'ip':ip,'category':cat,'version':ver,'discovered_url':f"http://{ip}"})
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

processed_results = {}
MY_PUBLIC_IP = None

# -----------------------------------------------------------------------------
# ScannerWorker with Realtime CSV Updates
# -----------------------------------------------------------------------------
class ScannerWorker:
    def __init__(self, settings):
        self.settings = settings
        self.timeout = int(settings["RequestTimeout"])
        self.seed_queue = queue.Queue()
        self.lock = threading.Lock()
        self.pbar = None

        # In-memory mappings for each CSV target.
        self.realtime_results = {
            "bulk": {},
            "whitelist": {},
            "potentially_up_bulk": {},
            "potentially_down_bulk": {},
            "winerror_bulk": {},
            "potentially_up_whitelist": {},
            "potentially_down_whitelist": {},
            "winerror_whitelist": {},
            "bulk_duplicate": {},
            "whitelist_duplicate": {},
            "potentially_up_bulk_duplicate": {},
            "potentially_down_bulk_duplicate": {},
            "winerror_bulk_duplicate": {},
            "potentially_up_whitelist_duplicate": {},
            "potentially_down_whitelist_duplicate": {},
            "winerror_whitelist_duplicate": {},
        }
        self.csv_file_paths = {
            "bulk": settings["BulkOutputFile"],
            "whitelist": settings["WhiteListOutputFile"],
            "potentially_up_bulk": settings["PotentiallyUpBulkOutputFile"],
            "potentially_down_bulk": settings["PotentiallyDownBulkOutputFile"],
            "winerror_bulk": settings["WinErrorBulkOutputFile"],
            "potentially_up_whitelist": settings["PotentiallyUpWhiteListOutputFile"],
            "potentially_down_whitelist": settings["PotentiallyDownWhiteListOutputFile"],
            "winerror_whitelist": settings["WinErrorWhitelistOutputFile"],
            "bulk_duplicate": settings["BulkDuplicateOutputFile"],
            "whitelist_duplicate": settings["WhiteListDuplicateOutputFile"],
            "potentially_up_bulk_duplicate": settings["PotentiallyUpBulkDuplicateOutputFile"],
            "potentially_down_bulk_duplicate": settings["PotentiallyDownBulkDuplicateOutputFile"],
            "winerror_bulk_duplicate": settings["WinErrorBulkDuplicateOutputFile"],
            "potentially_up_whitelist_duplicate": settings["PotentiallyUpWhiteListDuplicateOutputFile"],
            "potentially_down_whitelist_duplicate": settings["PotentiallyDownWhiteListDuplicateOutputFile"],
            "winerror_whitelist_duplicate": settings["WinErrorWhitelistDuplicateOutputFile"],
        }

    def write_csv_target(self, target):
        """Rewrites the entire CSV file for a given target from the in-memory mapping."""
        file_path = self.csv_file_paths[target]
        header = "IP,Categories,ReportDate,Comment\n"
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(header)
                for line in self.realtime_results[target].values():
                    f.write(line + "\n")
        except Exception as e:
            logging.error("Error writing CSV file %s: %s", file_path, e)

    def update_realtime_result(self, ip):
        data = processed_results[ip]
        report_date = datetime.now(timezone.utc).isoformat()
        # Recalculate accumulated categories and discovered URLs
        categories = sorted(data["categories"])
        all_categories = ",".join(categories)
        discovered_urls = ", ".join(sorted(data.get("discovered_urls", set())))
        similarity = data.get("similarity", 0.0)
        comment = data.get("last_comment", "").strip()
        # If duplicate, adjust the comment to reflect duplicate status
        is_duplicate = (data.get("count", 0) > 1) and (categories != ["whitelist"])
        if is_duplicate:
            comment = comment.replace("Yes it's not duplicate", "No it's duplicate")
        if len(categories) > 1:
            comment += " (Multiple categories: {})".format(all_categories)
        # Append discovered URLs info to the comment
        comment += " | Discovered URLs: {}".format(discovered_urls)
        # Determine CSV target based on duplicate flag and HTTP status
        if is_duplicate:
            if "whitelist" in data["categories"]:
                if data["status_type"] == "potentially_up":
                    target = "potentially_up_whitelist_duplicate"
                elif data["status_type"] == "potentially_down":
                    target = "potentially_down_whitelist_duplicate"
                elif data["status_type"] == "winerror":
                    target = "winerror_whitelist_duplicate"
                else:
                    target = "whitelist_duplicate"
            else:
                if data["status_type"] == "potentially_up":
                    target = "potentially_up_bulk_duplicate"
                elif data["status_type"] == "potentially_down":
                    target = "potentially_down_bulk_duplicate"
                elif data["status_type"] == "winerror":
                    target = "winerror_bulk_duplicate"
                else:
                    target = "bulk_duplicate"
        else:
            if "whitelist" in data["categories"]:
                if data["status_type"] == "potentially_up":
                    target = "potentially_up_whitelist"
                elif data["status_type"] == "potentially_down":
                    target = "potentially_down_whitelist"
                elif data["status_type"] == "winerror":
                    target = "winerror_whitelist"
                else:
                    target = "whitelist"
            else:
                if data["status_type"] == "potentially_up":
                    target = "potentially_up_bulk"
                elif data["status_type"] == "potentially_down":
                    target = "potentially_down_bulk"
                elif data["status_type"] == "winerror":
                    target = "winerror_bulk"
                else:
                    target = "bulk"

        # Remove the IP from all targets in case it moved
        for key in self.realtime_results:
            if ip in self.realtime_results[key]:
                del self.realtime_results[key][ip]
        self.realtime_results[target][ip] = f'{ip},"{all_categories}",{report_date},"{comment}"'
        self.write_csv_target(target)

    def process_seed(self, ip, category, version, discovered_url, initial_ip=False):
        # Initialize or update processed_results for the IP
        with self.lock:
            if ip not in processed_results:
                processed_results[ip] = {
                    "categories": set(),
                    "last_comment": "",
                    "count": 0,
                    "processed": False,
                    "status_type": "up",
                    "discovered_urls": set(),
                    "similarity": 0.0
                }
            processed_results[ip]["categories"].add(category)
            processed_results[ip]["count"] += 1
            processed_results[ip]["discovered_urls"].add(discovered_url)
            was_processed = processed_results[ip]["processed"]

        # If already processed, simply update the CSV row to reflect new categories or URLs
        if was_processed:
            with self.lock:
                self.update_realtime_result(ip)
            return

        with self.lock:
            processed_results[ip]["processed"] = True

        base_url = f"http://{ip}"
        visited = set()
        to_process = {base_url}
        base_content = None  # For HTML similarity comparison

        def process_page(url):
            nonlocal base_content
            new_pages = set()
            resp = None
            try:
                resp = requests.get(url, timeout=self.timeout, allow_redirects=True)
            except Exception as e:
                with self.lock:
                    processed_results[ip]['last_comment'] = str(e)
                    processed_results[ip]['status_type'] = 'winerror'
                    self.update_realtime_result(ip)
                return new_pages, resp

            if url == base_url and resp.status_code == 200:
                base_content = resp.text

            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'lxml')
                # 1) tag-based seeds
                for tag in soup.find_all(['script','link','img']):
                    attr = 'src' if tag.name!='link' else 'href'
                    val = tag.get(attr)
                    if not val: continue
                    full = urljoin(url, val)
                    parsed = urlparse(full)
                    if parsed.hostname == ip and full not in visited:
                        new_pages.add(full)
                    elif parsed.hostname and re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', parsed.hostname):
                        v2 = is_valid_ip(parsed.hostname)
                        if v2:
                            self.seed_queue.put({
                                'ip': parsed.hostname,
                                'category': category,
                                'version': v2,
                                'discovered_url': full
                            })

                # 2) inline-text seeds
                inline_ips = extract_ip_and_port(resp.text)
                for ip2, _, v2 in inline_ips:
                    if ip2 != ip:
                        self.seed_queue.put({
                            'ip': ip2,
                            'category': category,
                            'version': v2,
                            'discovered_url': url
                        })

                # 3) similarity + comment + CSV update
                sim = compute_similarity(resp.text, base_content) if (base_content and url!=base_url) else 0.0
                with self.lock:
                    processed_results[ip]['similarity'] = sim
                    code_str = f"{resp.status_code:03d}"
                    tmpl = (self.settings['CommentTemplateZerodayStatus200']
                            if resp.status_code==200 
                            else self.settings['CommentTemplateNoZeroday'])
                    processed_results[ip]['last_comment'] = tmpl.format(
                        ip=ip, discovered_url=discovered_url,
                        verdict=category, status=code_str, similarity=sim
                    )
                    processed_results[ip]['status_type'] = 'up' if resp.status_code==200 else 'potentially_down'
                    self.update_realtime_result(ip)
            else:
                # non-200 response handling
                with self.lock:
                    code_str = f"{resp.status_code:03d}" if resp else '000'
                    processed_results[ip]['last_comment'] = self.settings['CommentTemplateNoZeroday'].format(
                        ip=ip, discovered_url=discovered_url,
                        verdict=category, status=code_str
                    )
                    processed_results[ip]['status_type'] = 'potentially_down'
                    self.update_realtime_result(ip)

            return new_pages, resp

        # --- Main URL Processing Loop ---
        while to_process:
            current_url = to_process.pop()
            if current_url in visited:
                continue
            visited.add(current_url)
            new_urls, response = process_page(current_url)
            if response is None:
                continue

            # If not processing the base URL, compute similarity if base_content is available
            similarity = 0.0
            if current_url != base_url and base_content:
                similarity = compute_similarity(response.text, base_content)
            with self.lock:
                processed_results[ip]["similarity"] = similarity

            code_str = f"{response.status_code:03d}"
            up_codes = set(self.settings["HTTPUpCodes"].split(","))
            potentially_up_codes = set(self.settings["HTTPPotentiallyUpCodes"].split(","))
            potentially_down_codes = set(self.settings["HTTPPotentiallyDownCodes"].split(","))

            # Determine the appropriate comment and status based on the HTTP code
            if code_str in up_codes:
                if response.status_code == 200:
                    comment = self.settings["CommentTemplateZerodayStatus200"].format(
                        ip=ip, discovered_url=discovered_url, verdict=category, status=code_str, similarity=similarity
                    )
                else:
                    comment = self.settings["CommentTemplateZeroday"].format(
                        ip=ip, discovered_url=discovered_url, verdict=category, status=code_str
                    )
                status_type = "up"
            elif code_str in potentially_up_codes:
                comment = self.settings["CommentTemplateNoZeroday"].format(
                    ip=ip, discovered_url=discovered_url, verdict=category, status=code_str
                )
                status_type = "potentially_up"
            elif code_str in potentially_down_codes:
                comment = self.settings["CommentTemplateNoZeroday"].format(
                    ip=ip, discovered_url=discovered_url, verdict=category, status=code_str
                )
                status_type = "potentially_down"
            else:
                comment = self.settings["CommentTemplateNoZeroday"].format(
                    ip=ip, discovered_url=discovered_url, verdict=category, status=code_str
                )
                status_type = "up"

            with self.lock:
                processed_results[ip]["last_comment"] = comment
                processed_results[ip]["status_type"] = status_type

            to_process.update(new_urls - visited)

        # Always update the CSV row with the latest categories, discovered URLs, and similarity
        with self.lock:
            self.update_realtime_result(ip)

    def worker(self):
        while True:
            try:
                seed = self.seed_queue.get(timeout=5)
            except queue.Empty:
                break
            
            self.process_seed(
                seed["ip"],
                seed["category"],
                seed["version"],
                seed["discovered_url"]
            )
            self.seed_queue.task_done()
            
            with self.lock:
                if self.pbar:
                    self.pbar.update(1)

    def run(self, seeds):
        global MY_PUBLIC_IP
        # retrieve our public IP once
        MY_PUBLIC_IP = get_my_public_ip(self.timeout)

        # enqueue all seeds; processed_results entries created in process_seed()
        for seed in seeds:
            self.seed_queue.put(seed)

        # initialize progress bar
        initial_total = self.seed_queue.qsize()
        self.pbar = tqdm(total=initial_total, desc="Processing seeds")

        # start worker threads
        max_threads = min(int(self.settings["MaxThreads"]), initial_total)
        threads = []
        for _ in range(max_threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        # wait for completion
        self.seed_queue.join()
        for t in threads:
            t.join()

        # cleanup
        self.pbar.close()
        logging.info("Scan completed. (Results were written in real time.)")

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

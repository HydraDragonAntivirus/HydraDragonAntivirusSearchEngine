import os
import re
import sys
import json
import ipaddress
import threading
import requests
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
import concurrent.futures

from PySide6.QtCore import QObject, Signal, QThread, QThreadPool, QRunnable
from PySide6.QtGui import QIcon, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QProgressBar,
    QFileDialog,
    QGridLayout,
    QScrollArea,
    QTextEdit,
)

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
    filename=os.path.join(log_dir, "log.txt"),
    filemode="a"
)

# -----------------------------
# Antivirus Style
# -----------------------------
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
    min-width: 70px;
    font-weight: bold;
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
QLabel {
    color: #e0e0e0;
}
QLineEdit, QTextEdit {
    background-color: #3c3c3c;
    border: 1px solid #5a5a5a;
    padding: 4px;
}
QScrollArea {
    background-color: #2b2b2b;
}
"""

# -----------------------------
# Helper: Return canonical forms for an IP address.
# -----------------------------
def canonical_urls(ip):
    # Return the canonical http and https URLs (without trailing slash)
    return f"http://{ip}".rstrip('/'), f"https://{ip}".rstrip('/')

# -----------------------------
# Helper: Strip protocol from URL.
# -----------------------------
def strip_protocol(url):
    return re.sub(r'^https?://', '', url, flags=re.IGNORECASE).rstrip('/')

# -----------------------------
# Seed Class (metadata only)
# -----------------------------
class Seed:
    def __init__(self, ip, source_type, port=None):
        self.ip = ip.lower()
        self.source_type = source_type  # "malicious ipv4/v6", "bruteforce ipv4/v6", "spam ipv4/v6", "ddos ipv4/v6", "phishing ipv4/v6", or "whitelist ipv4/v6"
        self.port = port

    def get_url(self):
        return f"http://{self.ip}:{self.port}" if self.port else f"http://{self.ip}"

# -----------------------------
# SeedRunnable: Calls process_seed
# -----------------------------
class SeedRunnable(QRunnable):
    def __init__(self, seed, worker):
        super().__init__()
        self.seed = seed
        self.worker = worker

    def run(self):
        self.worker.process_seed(self.seed)

# -----------------------------
# ScannerWorker: Main scanning logic, duplicate rotation, and optimization.
# -----------------------------
class ScannerWorker(QObject):
    log_signal = Signal(str)
    progress_signal = Signal(int, int)
    finished_signal = Signal()
    failure = Signal(str)

    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.max_workers = int(settings.get("MaxThreads", 1000))
        self.user_csv_max_lines = int(settings.get("CsvMaxLines", 10000))
        self.csv_max_lines = self.user_csv_max_lines if self.user_csv_max_lines <= 10000 else 10000
        self.csv_max_size = int(settings.get("CsvMaxSize", 2097152))
        if self.user_csv_max_lines > 10000:
            self.log(f"CsvMaxLines set to {self.user_csv_max_lines} but enforced as 10,000.")
        self.comment_template_zeroday = settings.get(
            "CommentTemplateZeroday",
            "Related with ip address detected by heuristics of https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine (Discovered IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict}, HTTP Status: {status}), Zeroday: Yes it's not duplicate"
        )
        self.comment_template_nozeroday = settings.get(
            "CommentTemplateNoZeroday",
            "Related with ip address detected by heuristics of https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine (Discovered IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict}, HTTP Status: {status}), Zeroday: No it's duplicate"
        )
        self.allow_auto_verdict = settings.get("AllowAutoVerdict", True)
        self.request_timeout = int(settings.get("RequestTimeout", 10))
        self.out_bulk_csv = settings.get("OutputFile", default_bulk)
        self.out_whitelist_csv = settings.get("WhiteListOutputFile", default_whitelist)

        # Duplicate file paths from settings.
        self.duplicate_whitelist_file_ipv4 = settings.get("DuplicateWhitelistFileIPv4", "output\\whitelist_ipv4_duplicates.csv")
        self.duplicate_whitelist_file_ipv6 = settings.get("DuplicateWhitelistFileIPv6", "output\\whitelist_ipv6_duplicates.csv")
        self.duplicate_phishing_file_ipv4 = settings.get("DuplicatePhishingFileIPv4", "output\\phishing_ipv4_duplicates.csv")
        self.duplicate_phishing_file_ipv6 = settings.get("DuplicatePhishingFileIPv6", "output\\phishing_ipv6_duplicates.csv")
        self.duplicate_ddos_file_ipv4 = settings.get("DuplicateDDoSFileIPv4", "output\\ddos_ipv4_duplicates.csv")
        self.duplicate_ddos_file_ipv6 = settings.get("DuplicateDDoSFileIPv6", "output\\ddos_ipv6_duplicates.csv")
        self.duplicate_bruteforce_file_ipv4 = settings.get("DuplicateBruteForceFileIPv4", "output\\bruteforce_ipv4_duplicates.csv")
        self.duplicate_bruteforce_file_ipv6 = settings.get("DuplicateBruteForceFileIPv6", "output\\bruteforce_ipv6_duplicates.csv")
        self.duplicate_spam_file_ipv4 = settings.get("DuplicateSpamFileIPv4", "output\\spam_ipv4_duplicates.csv")
        self.duplicate_spam_file_ipv6 = settings.get("DuplicateSpamFileIPv6", "output\\spam_ipv6_duplicates.csv")
        self.duplicate_malicious_file_ipv4 = settings.get("DuplicateMaliciousFileIPv4", "output\\malicious_ipv4_duplicates.csv")
        self.duplicate_malicious_file_ipv6 = settings.get("DuplicateMaliciousFileIPv6", "output\\malicious_ipv6_duplicates.csv")

        self.my_public_ip = None
        self.lock = threading.Lock()
        self.cancelled = False
        self.visited_ips = set()  # for processing only once
        # New sets to differentiate initially loaded IPs vs. newly discovered ones.
        self.initial_ips = {
            "whitelist_ipv4": set(),
            "whitelist_ipv6": set(),
            "phishing_ipv4": set(),
            "phishing_ipv6": set(),
            "ddos_ipv4": set(),
            "ddos_ipv6": set(),
            "bruteforce_ipv4": set(),
            "bruteforce_ipv6": set(),
            "spam_ipv4": set(),
            "spam_ipv6": set(),
            "malicious_ipv4": set(),
            "malicious_ipv6": set()
        }

        # Main output rotation info
        self.bulk_file_index = 0
        self.whitelist_file_index = 0
        self.bulk_line_count = 0
        self.whitelist_line_count = 0
        self.bulk_file = None
        self.whitelist_file = None
        self.bulk_file_size = 0
        self.whitelist_file_size = 0

        self.processed_count = 0
        self.total_seeds = 0

        self.pause_event = threading.Event()
        self.pause_event.set()
        self.threadpool = QThreadPool()
        self.threadpool.setMaxThreadCount(self.max_workers)

        # Duplicate file info for rotation (per category key)
        self.dup_file_info = {
            "whitelist_ipv4": {"base": self.duplicate_whitelist_file_ipv4, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "whitelist_ipv6": {"base": self.duplicate_whitelist_file_ipv6, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "phishing_ipv4": {"base": self.duplicate_phishing_file_ipv4, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "phishing_ipv6": {"base": self.duplicate_phishing_file_ipv6, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "ddos_ipv4": {"base": self.duplicate_ddos_file_ipv4, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "ddos_ipv6": {"base": self.duplicate_ddos_file_ipv6, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "bruteforce_ipv4": {"base": self.duplicate_bruteforce_file_ipv4, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "bruteforce_ipv6": {"base": self.duplicate_bruteforce_file_ipv6, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "spam_ipv4": {"base": self.duplicate_spam_file_ipv4, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "spam_ipv6": {"base": self.duplicate_spam_file_ipv6, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "malicious_ipv4": {"base": self.duplicate_malicious_file_ipv4, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "malicious_ipv6": {"base": self.duplicate_malicious_file_ipv6, "index": 0, "line_count": 0, "file_size": 0, "handle": None}
        }

    def log(self, message):
        self.log_signal.emit(message)
        logging.info(message)

    def update_progress(self):
        self.progress_signal.emit(self.processed_count, self.total_seeds)

    def open_csv_files(self):
        for filename in [self.out_bulk_csv, self.out_whitelist_csv]:
            directory = os.path.dirname(filename)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
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
        for info in self.dup_file_info.values():
            if info["handle"]:
                info["handle"].close()
                info["handle"] = None

    def write_bulk_line(self, line):
        with self.lock:
            line_bytes = len(line.encode("utf-8"))
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
                self.log(f"Bulk file rotated; new file: {new_filename}")
            self.bulk_file.write(line)
            self.bulk_file.flush()
            self.bulk_line_count += 1
            self.bulk_file_size += line_bytes
            self.total_seeds += 1

    def write_whitelist_line(self, line):
        with self.lock:
            self.whitelist_file.write(line)
            self.whitelist_file.flush()
            self.whitelist_line_count += 1
            self.whitelist_file_size += len(line.encode("utf-8"))
            self.total_seeds += 1

    def write_duplicate_line(self, category, line):
        with self.lock:
            info = self.dup_file_info.get(category)
            if info is None:
                self.log(f"[ERROR] No duplicate file info for category {category}")
                return
            if info["handle"] is None:
                base, ext = os.path.splitext(info["base"])
                filename = f"{base}_{info['index']}{ext}"
                handle = open(filename, "w", encoding="utf-8")
                header = "IP,Categories,ReportDate,Comment\n"
                handle.write(header)
                handle.flush()
                info["line_count"] = 1
                info["file_size"] = len(header.encode("utf-8"))
                info["handle"] = handle
            line_bytes = len(line.encode("utf-8"))
            if info["line_count"] >= self.csv_max_lines or (info["file_size"] + line_bytes) >= self.csv_max_size:
                info["handle"].close()
                info["index"] += 1
                base, ext = os.path.splitext(info["base"])
                new_filename = f"{base}_{info['index']}{ext}"
                handle = open(new_filename, "w", encoding="utf-8")
                header = "IP,Categories,ReportDate,Comment\n"
                handle.write(header)
                handle.flush()
                info["line_count"] = 1
                info["file_size"] = len(header.encode("utf-8"))
                info["handle"] = handle
                self.log(f"Duplicate file for {category} rotated; new file: {new_filename}")
            info["handle"].write(line)
            info["handle"].flush()
            info["line_count"] += 1
            info["file_size"] += line_bytes

    def handle_duplicate(self, category, seed, status, discovered_source_url):
        report_date = datetime.now(timezone.utc).isoformat()
        comment = self.comment_template_nozeroday.format(ip=seed.ip,
                                                         discovered_url=discovered_source_url,
                                                         verdict=seed.source_type,
                                                         status=status)
        line = f'{seed.ip},"",{report_date},"{comment}"\n'
        self.write_duplicate_line(category, line)
        self.log(f"Duplicate recorded for {seed.ip} in duplicate file {category} with status {status}.")

    def run_scan(self):
        self.log("Loading definitions...")
        self.my_public_ip = self.get_my_public_ip()
        seeds = self.load_seeds()
        if not seeds:
            self.log("No seed IP addresses found.")
            self.finished_signal.emit()
            return
        with self.lock:
            self.total_seeds = len(seeds)
        self.log(f"Starting with {len(seeds)} initial seeds.")
        self.open_csv_files()
        for seed in seeds:
            self.threadpool.start(SeedRunnable(seed, self))
        self.threadpool.waitForDone()
        self.close_csv_files()
        self.log("Scan completed.")
        self.finished_signal.emit()

    def process_seed(self, seed, discovered_source_url=None):
        if seed.ip in self.visited_ips:
            self.log(f"Skipping {seed.ip} (already visited).")
            return

        if self.my_public_ip and seed.ip == self.my_public_ip:
            self.log(f"Skipping my own public IP: {ip}")
            return

        if seed.ip.startswith("https://") or seed.ip.startswith("http://"):
            seed.ip = urlparse(seed.ip).hostname
            self.visited_ips.add(seed.ip)

        cat = seed.source_type.lower().strip()
        allowed_categories = [
            "whitelist_ipv6", "whitelist_ipv4",
            "phishing_ipv6", "phishing_ipv4",
            "ddos_ipv6", "ddos_ipv4",
            "bruteforce_ipv6", "bruteforce_ipv4",
            "spam_ipv6", "spam_ipv4",
            "malicious_ipv6", "malicious_ipv4",
        ]
        if cat not in allowed_categories:
            self.log(f"Category for {seed.ip} is '{cat}', which is not allowed. Skipping processing.")
            return

        if not discovered_source_url:
            discovered_source_url = seed.get_url()  # Default discovered URL

        # Call is_active_and_static only once.
        status = self.is_active_and_static(seed.ip, seed.port, category=cat, discovered_source_url=discovered_source_url)
        
        if status is None:
            self.log(f"Skipping {seed.ip} due to unavailable HTTP status.")
            return

        # Duplicate flag
        duplicate_flag = False 

        # If duplicate, log duplicate with the same status and return.
        if seed.ip in self.initial_ips.get(cat, set()):
                duplicate_flag = True

        # Duplicate settings
        duplicate_settings = False

        allow_duplicate_key = f"AllowDuplicate{seed.source_type.capitalize()}"
        if self.settings.get(allow_duplicate_key, True):
                duplicate_settings = True

        # Determine seed_verdict based on category and HTTP status.
        if cat.startswith("whitelist"):
            seed_verdict = "whitelist (auto verdict 2)" if 200 <= status <= 299 else "whitelist (auto verdict 3)"
        elif cat.startswith("phishing"):
            if 200 <= status <= 299:
                seed_verdict = "phishing (auto verdict 5)"
            elif 300 <= status <= 399:
                seed_verdict = "phishing (auto verdict 6)"
            else:
                seed_verdict = "whitelist (auto verdict 2)"
        elif cat.startswith("spam"):
            if 200 <= status <= 299:
                seed_verdict = "spam (auto verdict 5)"
            elif 300 <= status <= 399:
                seed_verdict = "spam (auto verdict 6)"
            else:
                seed_verdict = "whitelist (auto verdict 2)"
        elif cat.startswith("ddos"):
            if 200 <= status <= 299:
                seed_verdict = "ddos (auto verdict 5)"
            elif 300 <= status <= 399:
                seed_verdict = "ddos (auto verdict 6)"
            else:
                seed_verdict = "whitelist (auto verdict 1)"
        elif cat.startswith("bruteforce"):
            if 200 <= status <= 299:
                seed_verdict = "bruteforce (auto verdict 5)"
            elif 300 <= status <= 399:
                seed_verdict = "bruteforce (auto verdict 6)"
            else:
                seed_verdict = "whitelist (auto verdict 1)"
        elif cat.startswith("malicious"):
            if 200 <= status <= 299:
                seed_verdict = "malicious (auto verdict 5)"
            elif 300 <= status <= 399:
                seed_verdict = "malicious (auto verdict 6)"
            else:
                seed_verdict = "whitelist (auto verdict 1)"
        else:
            seed_verdict = seed.source_type

        # Build the comment using the updated template (includes {status}).
        if seed_verdict.startswith("whitelist"):
            comment = self.comment_template_zeroday.format(ip=seed.ip,
                                                           discovered_url=discovered_source_url,
                                                           verdict=seed_verdict,
                                                           status=status)
            line = f'{seed.ip},"",{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
            if not duplicate_flag:
                self.write_whitelist_line(line)
                self.log(f"Whitelist output written for {seed.ip}.")
            elif duplicate_flag and duplicate_settings:
                 self.handle_duplicate(cat, seed, status, discovered_source_url)
            elif duplicate_flag and not duplicate_settings:
                 self.log(f"Duplicate for {seed.ip} detected. Skipping adding.")
        else:
            if cat.startswith("phishing"):
                cat_label = self.settings.get("CategoryPhishing", "7")
            elif cat.startswith("ddos"):
                cat_label = self.settings.get("CategoryDDoS", "4")
            elif cat.startswith("bruteforce"):
                cat_label = self.settings.get("CategoryBruteForce", "18")
            elif cat.startswith("spam"):
                cat_label = self.settings.get("CategorySpam", "10")
            elif cat.startswith("malicious"):
                cat_label = self.settings.get("CategoryMalicious", "20")
            else:
                self.log("Invalid label returning...")
                return
            comment = self.comment_template_zeroday.format(ip=seed.ip,
                                                           discovered_url=discovered_source_url,
                                                           verdict=seed_verdict,
                                                           status=status)
            line = f'{seed.ip},"{cat_label}",{datetime.now(timezone.utc).isoformat()},"{comment}"\n'
            if not duplicate_flag:
                self.write_bulk_line(line)
                self.log(f"Bulk output written for {seed.ip}.")
            elif duplicate_flag and duplicate_settings:
                self.handle_duplicate(cat, seed, status, discovered_source_url)
            elif duplicate_flag and not duplicate_settings:
                self.log(f"Duplicate for {seed.ip} detected. Skipping adding.")
        with self.lock:
            self.processed_count += 1
            self.update_progress()

    def is_active_and_static(self, ip, port, timeout=None, category=None, discovered_source_url=None):
        if timeout is None:
            timeout = self.request_timeout

        # If the IP is IPv6, wrap it in brackets.
        if self.is_valid_ip(ip) == "ipv6":
            url = f"http://[{ip}]" + (f":{port}" if port else "")
        else:
            url = f"http://{ip}" + (f":{port}" if port else "")

        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            code = response.status_code

            # Process responses in the active range: 200-299 and 300-399.
            if 200 <= code <= 399:
                # Always extract the final hostname from the response URL.
                parsed_ip = urlparse(response.url).hostname
                if parsed_ip and parsed_ip != ip and self.is_valid_ip(parsed_ip):
                    new_seed = Seed(parsed_ip, category, port=port)
                    self.log(f"Processing redirected IP: {new_seed} (Category: {category}) - HTTP {code}")
                    self.process_seed(new_seed, discovered_source_url=discovered_source_url)
                # Extract discovered IPs from the response content.
                found_ips = self.extract_ip_and_port(response.text)
                for extracted_ip, extracted_port, ip_version in found_ips:
                    if ip_version == "ipv6":
                        # If the IPv6 address is not already enclosed in brackets, add them.
                        if not (extracted_ip.startswith('[') and extracted_ip.endswith(']')):
                            candidate = "http://[" + extracted_ip + "]"
                        else:
                            # If it already has brackets, remove them so that we can parse correctly.
                            candidate = "http://" + extracted_ip[1:-1]
                    else:
                        candidate = extracted_ip if extracted_ip.lower().startswith("http") else "http://" + extracted_ip
                    # Parse the candidate extracted IP to get the hostname.
                    parsed_extracted = urlparse(candidate).hostname
                    discovered_ip = parsed_extracted if parsed_extracted is not None else extracted_ip
                    new_seed = Seed(discovered_ip, category, port=extracted_port)
                    self.log(f"Processing discovered IP: {new_seed} (Category: {category}) - HTTP {code}")
                    self.process_seed(new_seed, discovered_source_url=discovered_source_url)
            elif 400 <= code <= 499:
                self.log(f"Client error: HTTP {code} for {url}")
            elif 500 <= code <= 599:
                self.log(f"Server error: HTTP {code} for {url}")
            elif 100 <= code <= 199:
                self.log(f"Info: HTTP {code} for {url}")
            else:
                self.log(f"Unhandled HTTP status code {code} for {url}")

            return code

        except Exception as e:
            self.log(f"Active/static check failed for {url}: {e}")
            return None

    def get_my_public_ip(self):
        try:
            response = requests.get("https://api.ipify.org", timeout=self.request_timeout)
            ip = response.text.strip()
            self.log(f"My public IP is {ip}")
            return ip
        except Exception as e:
            self.log(f"Could not determine public IP: {e}")
            self.failure.emit(f"Could not determine public IP: {e}")
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
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split(",", 1)
                    ip = parts[0].strip().lower()
                    if ip and self.is_valid_ip(ip):
                        entries.append(ip)
        self.log(f"Loaded {len(entries)} valid IP entries from {path}")
        return entries

    def load_seeds(self):
        seeds = []
        loaded_ips = set()
        file_category_mapping = {}
        def add_file(file, source_type):
            if file not in file_category_mapping:
                file_category_mapping[file] = []
            file_category_mapping[file].append((source_type))
        for file in [x.strip() for x in self.settings.get("WhiteListFilesIPv6", "").split(",") if x.strip()]:
            add_file(file, "whitelist_ipv6")
        for file in [x.strip() for x in self.settings.get("WhiteListFilesIPv4", "").split(",") if x.strip()]:
            add_file(file, "whitelist_ipv4")
        for file in [x.strip() for x in self.settings.get("PhishingFilesIPv6", "").split(",") if x.strip()]:
            add_file(file, "phishing_ipv6")
        for file in [x.strip() for x in self.settings.get("PhishingFilesIPv4", "").split(",") if x.strip()]:
            add_file(file, "phishing_ipv4")
        for file in [x.strip() for x in self.settings.get("DDoSFilesIPv6", "").split(",") if x.strip()]:
            add_file(file, "ddos_ipv6")
        for file in [x.strip() for x in self.settings.get("DDoSFilesIPv4", "").split(",") if x.strip()]:
            add_file(file, "ddos_ipv4")
        for file in [x.strip() for x in self.settings.get("BruteForceFilesIPv6", "").split(",") if x.strip()]:
            add_file(file, "bruteforce_ipv6")
        for file in [x.strip() for x in self.settings.get("BruteForceFilesIPv4", "").split(",") if x.strip()]:
            add_file(file, "bruteforce_ipv4")
        for file in [x for x in self.settings.get("SpamFilesIPv6", "").split(",") if x.strip()]:
            add_file(file, "spam_ipv6")
        for file in [x for x in self.settings.get("SpamFilesIPv4", "").split(",") if x.strip()]:
            add_file(file, "spam_ipv4")
        for file in [x.strip() for x in self.settings.get("MalwareFilesIPv6", "").split(",") if x.strip()]:
            add_file(file, "malicious_ipv6")
        for file in [x.strip() for x in self.settings.get("MalwareFilesIPv4", "").split(",") if x.strip()]:
            add_file(file, "malicious_ipv4")
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
                    if ip not in loaded_ips:
                        seed = Seed(ip, source_type)
                        seeds.append(seed)
                        loaded_ips.add(ip)
                        # Add loaded IP to the appropriate initial set.
                        key = f"{source_type.lower()}"
                        self.initial_ips.setdefault(key, set()).add(ip)
        self.log(f"Total valid seeds loaded: {len(seeds)}")
        return seeds

    def pause(self):
        self.pause_event.clear()
        self.log("Scan paused.")

    def resume(self):
        self.pause_event.set()
        self.log("Scan resumed.")

# -----------------------------
# MainWindow: Settings GUI
# -----------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hydra Dragon Antivirus Search Engine")
        self.setWindowIcon(QIcon("assets/HydraDragonAV.png"))
        self.worker = None
        self.thread = None
        self.is_scanning = False
        self.is_paused = False
        self.setup_ui()

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        settings_group = QWidget()
        settings_layout = QGridLayout(settings_group)
        row = 0

        # Define keys for which a browse button should be added.
        file_keys = {
            "OutputFile", "WhiteListOutputFile",
            "DuplicateWhitelistFileIPv4", "DuplicateWhitelistFileIPv6",
            "DuplicatePhishingFileIPv4", "DuplicatePhishingFileIPv6",
            "DuplicateDDoSFileIPv6", "DuplicateDDoSFileIPv4",
            "DuplicateBruteForceFileIPv4", "DuplicateBruteForceFileIPv6",
            "DuplicateSpamFileIPv4", "DuplicateSpamFileIPv6",
            "DuplicateMaliciousFileIPv4", "DuplicateMaliciousFileIPv6"
        }

        directory_keys = {"LastPath"}

        # Modified add_field: adds a browse button for file/directory selection if needed.
        def add_field(label_text, key, default=""):
            nonlocal row
            current_row = row
            lbl = QLabel(label_text)
            le = QLineEdit(str(default))
            settings_layout.addWidget(lbl, current_row, 0)
            settings_layout.addWidget(le, current_row, 1)
            # Check if this key should have a browse button.
            if key in file_keys:
                browse_btn = QPushButton("Browse File")
                def browse_file():
                    file_path, _ = QFileDialog.getSaveFileName(self, "Select CSV File", le.text(), "CSV Files (*.csv)")
                    if file_path:
                        le.setText(file_path)
                browse_btn.clicked.connect(browse_file)
                settings_layout.addWidget(browse_btn, current_row, 2)
            elif key in directory_keys:
                browse_btn = QPushButton("Browse Directory")
                def browse_directory():
                    directory = QFileDialog.getExistingDirectory(self, "Select Directory", le.text())
                    if directory:
                        le.setText(directory)
                browse_btn.clicked.connect(browse_directory)
                settings_layout.addWidget(browse_btn, current_row, 2)
            self.fields[key] = le
            row = current_row + 1

        self.fields = {}
        def add_plain_field(label_text, key, default=""):
            # Original add_field without browse button
            nonlocal row
            lbl = QLabel(label_text)
            le = QLineEdit(str(default))
            settings_layout.addWidget(lbl, row, 0)
            settings_layout.addWidget(le, row, 1)
            self.fields[key] = le
            row += 1

        # Basic settings (these remain unchanged)
        add_plain_field("Max Threads:", "MaxThreads", 1000)
        add_plain_field("CsvMaxLines:", "CsvMaxLines", 10000)
        add_plain_field("CsvMaxSize (bytes):", "CsvMaxSize", 2097152)
        # CSV file fields now use the modified add_field with browse button
        add_field("Bulk Report File:", "OutputFile", default_bulk)
        add_field("Whitelist Report File:", "WhiteListOutputFile", default_whitelist)
        add_plain_field("Category Phishing:", "CategoryPhishing", "7")
        add_plain_field("Category DDoS:", "CategoryDDoS", "4")
        add_plain_field("Category BruteForce:", "CategoryBruteForce", "18")
        add_plain_field("Category Spam:", "CategorySpam", "10")
        add_plain_field("Category Malicious:", "CategoryMalicious", "20")
        add_plain_field("Comment Template Zeroday:", "CommentTemplateZeroday", "Related with ip address detected by heuristics of https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine (Discovered IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict}, HTTP Status: {status}), Zeroday: Yes it's not duplicate")
        add_plain_field("Comment Template No Zeroday (Duplicate):", "CommentTemplateNoZeroday", "Related with ip address detected by heuristics of https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine (Discovered IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict}, HTTP Status: {status}), Zeroday: No it's duplicate")
        add_plain_field("MalwareFilesIPv6 (comma-separated):", "MalwareFilesIPv6", "website\\IPv6Malware.txt")
        add_plain_field("MalwareFilesIPv4 (comma-separated):", "MalwareFilesIPv4", "website\\IPv4Malware.txt")
        add_plain_field("BruteForceFilesIPv6 (comma-separated):", "BruteForceFilesIPv6", "")
        add_plain_field("BruteForceFilesIPv4 (comma-separated):", "BruteForceFilesIPv4", "website\\IPv4BruteForce.txt")
        add_plain_field("SpamFilesIPv6 (comma-separated):", "SpamIPv6", "website\\IPv6Spam.txt")
        add_plain_field("SpamFilesIPv4 (comma-separated):", "SpamFilesIPv4", "website\\IPv4Spam.txt")
        add_plain_field("PhishingFilesIPv6 (comma-separated):", "PhishingFilesIPv6", "")
        add_plain_field("PhishingFilesIPv4 (comma-separated):", "PhishingFilesIPv4", "website\\IPv4PhishingActive.txt, website\\IPv4PhishingInActive.txt")
        add_plain_field("DDoSFilesIPv6 (comma-separated):", "DDoSFilesIPv6", "website\\IPv6DDoS.txt")
        add_plain_field("DDoSFilesIPv4 (comma-separated):", "DDoSFilesIPv4", "website\\IPv4DDoS.txt")
        add_plain_field("WhiteListFilesIPv6 (comma-separated):", "WhiteListFilesIPv6", "website\\IPv6WhiteList.txt")
        add_plain_field("WhiteListFilesIPv4 (comma-separated):", "WhiteListFilesIPv4", "website\\IPv4WhiteList.txt")
        add_plain_field("WhiteList Path IPv4:", "WhiteListPathIPv4", "website\\IPv4WhiteList.txt")
        add_plain_field("WhiteList Path IPv6:", "WhiteListPathIPv6", "website\\IPv6WhiteList.txt")
        add_plain_field("Phishing Path IPv4:", "PhishingPathIPv4", "website\\IPv4Phishing.txt")
        add_plain_field("Phishing Path IPv6:", "PhishingPathIPv6", "website\\IPv6Phishing.txt")
        # Last Directory Path uses a directory browse button
        add_field("Last Directory Path:", "LastPath", "website")
        add_plain_field("Allow Duplicate Whitelist IPv4 (true/false):", "AllowDuplicateWhitelistIPv4", "true")
        add_plain_field("Allow Duplicate Whitelist IPv6 (true/false):", "AllowDuplicateWhitelistIPv6", "true")
        add_plain_field("Allow Duplicate Phishing IPv4 (true/false):", "AllowDuplicatePhishingIPv4", "true")
        add_plain_field("Allow Duplicate Phishing IPv6 (true/false):", "AllowDuplicatePhishingIPv6", "true")
        add_plain_field("Allow Duplicate BruteForce IPv4 (true/false):", "AllowDuplicateBruteForceIPv4", "true")
        add_plain_field("Allow Duplicate BruteForce IPv6 (true/false):", "AllowDuplicateBruteForceIPv6", "true")
        add_plain_field("Allow Duplicate Spam IPv4 (true/false):", "AllowDuplicateSpamIPv4", "true")
        add_plain_field("Allow Duplicate Spam IPv6 (true/false):", "AllowDuplicateSpamIPv6", "true")
        add_plain_field("Allow Duplicate Malicious IPv4 (true/false):", "AllowDuplicateMaliciousIPv4", "true")
        add_plain_field("Allow Duplicate Malicious IPv6 (true/false):", "AllowDuplicateMaliciousIPv6", "true")
        # Duplicate file fields (CSV) use browse buttons
        add_field("Duplicate Whitelist File IPv4:", "DuplicateWhitelistFileIPv4", "output\\whitelist_ipv4_duplicates.csv")
        add_field("Duplicate Whitelist File IPv6:", "DuplicateWhitelistFileIPv6", "output\\whitelist_ipv6_duplicates.csv")
        add_field("Duplicate Phishing File IPv4:", "DuplicatePhishingFileIPv4", "output\\phishing_ipv4_duplicates.csv")
        add_field("Duplicate Phishing File IPv6:", "DuplicatePhishingFileIPv6", "output\\phishing_ipv6_duplicates.csv")
        add_field("Duplicate DDoS File IPv6:", "DuplicateDDoSFileIPv6", "output\\ddos_ipv6_duplicates.csv")
        add_field("Duplicate DDoS File IPv4:", "DuplicateDDoSFileIPv4", "output\\ddos_ipv4_duplicates.csv")
        add_field("Duplicate BruteForce File IPv4:", "DuplicateBruteForceFileIPv4", "output\\bruteforce_ipv4_duplicates.csv")
        add_field("Duplicate BruteForce File IPv6:", "DuplicateBruteForceFileIPv6", "output\\bruteforce_ipv6_duplicates.csv")
        add_field("Duplicate Spam File IPv4:", "DuplicateSpamFileIPv4", "output\\spam_ipv4_duplicates.csv")
        add_field("Duplicate Spam File IPv6:", "DuplicateSpameFileIPv6", "output\\spam_ipv6_duplicates.csv")
        add_field("Duplicate Malicious File IPv4:", "DuplicateMaliciousFileIPv4", "output\\malicious_ipv4_duplicates.csv")
        add_field("Duplicate Malicious File IPv6:", "DuplicateMaliciousFileIPv6", "output\\malicious_ipv6_duplicates.csv")
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(settings_group)
        main_layout.addWidget(scroll)
        btn_layout = QHBoxLayout()
        self.load_btn = QPushButton("Load Settings")
        self.load_btn.clicked.connect(self.load_settings)
        self.save_btn = QPushButton("Save Settings")
        self.save_btn.clicked.connect(self.save_settings)
        btn_layout.addWidget(self.load_btn)
        btn_layout.addWidget(self.save_btn)
        main_layout.addLayout(btn_layout)
        control_layout = QHBoxLayout()
        self.start_stop_button = QPushButton("Start Scan")
        self.start_stop_button.clicked.connect(self.toggle_scan)
        control_layout.addWidget(self.start_stop_button)
        self.pause_button = QPushButton("Pause Scan")
        self.pause_button.clicked.connect(self.toggle_pause)
        self.pause_button.setVisible(False)
        control_layout.addWidget(self.pause_button)
        main_layout.addLayout(control_layout)
        self.progress_bar = QProgressBar()
        main_layout.addWidget(self.progress_bar)
        search_layout = QHBoxLayout()
        self.search_line = QLineEdit()
        self.search_line.setPlaceholderText("Search log...")
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.search_log)
        self.clear_search_button = QPushButton("Clear Search")
        self.clear_search_button.clicked.connect(self.clear_search)
        search_layout.addWidget(QLabel("Log Search:"))
        search_layout.addWidget(self.search_line)
        search_layout.addWidget(self.search_button)
        search_layout.addWidget(self.clear_search_button)
        main_layout.addLayout(search_layout)
        main_layout.addWidget(QLabel("Log:"))
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        main_layout.addWidget(self.log_text)

    def get_settings_from_fields(self):
        settings = {}
        bool_keys = ("AllowAutoVerdict",
                     "AllowDuplicateWhitelistIPv4", "AllowDuplicateWhitelistIPv6",
                     "AllowDuplicatePhishingIPv4", "AllowDuplicatePhishingIPv6",
                     "AllowDuplicateBruteForceIPv4", "AllowDuplicateBruteForceIPv6",
                     "AllowDuplicateMaliciousIPv4", "AllowDuplicateMaliciousIPv6")
        for key, le in self.fields.items():
            value = le.text().strip()
            if key in ("MaxThreads", "CsvMaxLines", "CsvMaxSize"):
                try:
                    value = int(value)
                except:
                    value = 0
            if key in bool_keys:
                value = value.lower() == "true"
            settings[key] = value
        return settings

    def load_settings(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Settings JSON", os.getcwd(), "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    settings = json.load(f)
                for key, value in settings.items():
                    if key in self.fields:
                        self.fields[key].setText(str(value))
                self.append_log("Settings loaded successfully.")
            except Exception as e:
                self.append_log(f"Failed to load settings: {e}")

    def save_settings(self):
        settings = self.get_settings_from_fields()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Settings JSON", os.getcwd(), "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(settings, f, indent=4)
                self.append_log("Settings saved successfully.")
            except Exception as e:
                self.append_log(f"Failed to save settings: {e}")

    def toggle_scan(self):
        if not self.is_scanning:
            self.start_scan()
            self.start_stop_button.setText("Stop Scan")
            self.pause_button.setVisible(True)
            self.pause_button.setText("Pause Scan")
            self.is_scanning = True
        else:
            self.stop_scan()
            self.start_stop_button.setText("Start Scan")
            self.pause_button.setVisible(False)
            self.is_scanning = False
            self.is_paused = False

    def toggle_pause(self):
        if not self.is_scanning or not self.worker:
            return
        if not self.is_paused:
            self.worker.pause()
            self.pause_button.setText("Resume Scan")
            self.is_paused = True
        else:
            self.worker.resume()
            self.pause_button.setText("Pause Scan")
            self.is_paused = False

    def start_scan(self):
        settings = self.get_settings_from_fields()
        self.settings = settings
        self.append_log("Starting scan...")
        self.worker = ScannerWorker(settings)
        self.worker.log_signal.connect(self.append_log)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.finished_signal.connect(self.scan_finished)
        self.worker.failure.connect(self.append_log)
        self.thread = QThread()
        self.worker.moveToThread(self.thread)
        self.scan_start_time = time.time()
        self.thread.started.connect(self.worker.run_scan)
        self.thread.start()

    def stop_scan(self):
        if self.worker:
            self.worker.cancelled = True
            self.append_log("Scan cancellation requested.")

    def append_log(self, message):
        self.log_text.append(message)

    def update_progress(self, processed, total):
        self.progress_bar.setMaximum(total if total > 0 else 1)
        self.progress_bar.setValue(processed)
        percent = (processed / total * 100) if total > 0 else 0
        if processed > 0:
            elapsed = time.time() - self.scan_start_time
            average_time = elapsed / processed
            remaining_time = average_time * (total - processed)
            eta = time.strftime("%H:%M:%S", time.gmtime(remaining_time))
        else:
            eta = "Calculating..."
        self.progress_bar.setFormat(f"{processed}/{total} ({percent:.0f}%) - ETA: {eta}")

    def scan_finished(self):
        self.append_log("Scan finished.")
        self.start_stop_button.setText("Start Scan")
        self.pause_button.setVisible(False)
        self.is_scanning = False
        self.is_paused = False
        if self.thread:
            self.thread.quit()
            self.thread.wait()

    def search_log(self):
        search_text = self.search_line.text().strip()
        if not search_text:
            return
        if not self.log_text.find(search_text):
            self.log_text.moveCursor(QTextCursor.Start)
            if not self.log_text.find(search_text):
                self.append_log(f'No matches found for "{search_text}".')

    def clear_search(self):
        cursor = self.log_text.textCursor()
        cursor.clearSelection()
        self.log_text.setTextCursor(cursor)
        self.log_text.moveCursor(QTextCursor.End)

def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(antivirus_style)
    window = MainWindow()
    window.resize(800, 600)
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
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

log_dir = "log"
output_dir = "output"
default_bulk = os.path.join(output_dir, "BulkReport.csv")
default_whitelist = os.path.join(output_dir, "WhitelistReport.csv")
os.makedirs(log_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)

# -----------------------------
# Configure Logging: Redirect logs to log/log.txt
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
# Seed class – is_input is stored for metadata only.
# -----------------------------
class Seed:
    def __init__(self, ip, source_type, version, port=None, is_input=True):
        self.ip = ip.lower()
        # source_type: "malicious", "ddos", "phishing", or "benign"
        self.source_type = source_type  
        self.version = version  # "ipv4" or "ipv6"
        self.port = port
        self.is_input = is_input

    def get_url(self):
        return f"http://{self.ip}:{self.port}" if self.port else f"http://{self.ip}"

# -----------------------------
# SeedRunnable: A QRunnable that calls process_seed
# -----------------------------
class SeedRunnable(QRunnable):
    def __init__(self, seed, worker):
        super().__init__()
        self.seed = seed
        self.worker = worker

    def run(self):
        self.worker.process_seed(self.seed)

# -----------------------------
# ScannerWorker with duplicate file rotation and optimization.
# -----------------------------
class ScannerWorker(QObject):
    log_signal = Signal(str)
    progress_signal = Signal(int, int)  # processed, total
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
            self.log(f"CsvMaxLines set to {self.user_csv_max_lines} but will be enforced as 10,000 per file due to AbuseIPDB limits.")
        self.comment_template = settings.get("CommentTemplate", 
            "Related with ip address detected by heuristics of https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine (Source IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict})"
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
        self.duplicate_malicious_file_ipv4 = settings.get("DuplicateMaliciousFileIPv4", "output\\malicious_ipv4_duplicates.csv")
        self.duplicate_malicious_file_ipv6 = settings.get("DuplicateMaliciousFileIPv6", "output\\malicious_ipv6_duplicates.csv")
        
        # Duplicate tracking sets (to avoid logging the same duplicate twice)
        self.duplicate_whitelist_set_ipv4 = set()
        self.duplicate_whitelist_set_ipv6 = set()
        self.duplicate_phishing_set_ipv4 = set()
        self.duplicate_phishing_set_ipv6 = set()
        self.duplicate_ddos_set_ipv4 = set()
        self.duplicate_ddos_set_ipv6 = set()
        self.duplicate_malicious_set_ipv4 = set()
        self.duplicate_malicious_set_ipv6 = set()

        self.my_public_ip = None
        self.lock = threading.Lock()
        self.cancelled = False

        # Prevent duplicate processing (each IP processed only once)
        self.visited_ips = set()

        # Track which IPs have been written to main output (to prevent duplicates there)
        self.output_ips = {
            "whitelist_ipv4": set(),
            "whitelist_ipv6": set(),
            "phishing_ipv4": set(),
            "phishing_ipv6": set(),
            "ddos_ipv4": set(),
            "ddos_ipv6": set(),
            "malicious_ipv4": set(),
            "malicious_ipv6": set()
        }

        # CSV splitting variables for main output
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

        # Initialize duplicate file info for rotation (per category key).
        self.dup_file_info = {
            "whitelist_ipv4": {"base": self.duplicate_whitelist_file_ipv4, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "whitelist_ipv6": {"base": self.duplicate_whitelist_file_ipv6, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "phishing_ipv4": {"base": self.duplicate_phishing_file_ipv4, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "phishing_ipv6": {"base": self.duplicate_phishing_file_ipv6, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "ddos_ipv4": {"base": self.duplicate_ddos_file_ipv4, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "ddos_ipv6": {"base": self.duplicate_ddos_file_ipv6, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "malicious_ipv4": {"base": self.duplicate_malicious_file_ipv4, "index": 0, "line_count": 0, "file_size": 0, "handle": None},
            "malicious_ipv6": {"base": self.duplicate_malicious_file_ipv6, "index": 0, "line_count": 0, "file_size": 0, "handle": None}
        }

    def log(self, message):
        self.log_signal.emit(message)
        logging.info(message)

    def update_progress(self):
        self.progress_signal.emit(self.processed_count, self.total_seeds)

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

    def write_whitelist_line(self, line):
        with self.lock:
            self.whitelist_file.write(line)
            self.whitelist_file.flush()
            self.whitelist_line_count += 1
            self.whitelist_file_size += len(line.encode("utf-8"))

    def write_duplicate_line(self, key, line):
        with self.lock:
            info = self.dup_file_info.get(key)
            if info is None:
                self.log(f"[ERROR] No duplicate file info for key {key}")
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
                self.log(f"Duplicate file for {key} rotated; new file: {new_filename}")
            info["handle"].write(line)
            info["handle"].flush()
            info["line_count"] += 1
            info["file_size"] += line_bytes

    def handle_duplicate(self, category, seed):
        # Determine duplicate key based on category and IP version.
        if category.startswith("benign"):
            key = "whitelist_" + seed.version
        elif category == "phishing":
            key = "phishing_" + seed.version
        elif category == "ddos":
            key = "ddos_" + seed.version
        elif category == "malicious":
            key = "malicious_" + seed.version
        else:
            self.log(f"[ERROR] No duplicate file configured for category {category}")
            return
        with self.lock:
            dup_set = None
            if key == "whitelist_ipv4":
                dup_set = self.duplicate_whitelist_set_ipv4
            elif key == "whitelist_ipv6":
                dup_set = self.duplicate_whitelist_set_ipv6
            elif key == "phishing_ipv4":
                dup_set = self.duplicate_phishing_set_ipv4
            elif key == "phishing_ipv6":
                dup_set = self.duplicate_phishing_set_ipv6
            elif key == "ddos_ipv4":
                dup_set = self.duplicate_ddos_set_ipv4
            elif key == "ddos_ipv6":
                dup_set = self.duplicate_ddos_set_ipv6
            elif key == "malicious_ipv4":
                dup_set = self.duplicate_malicious_set_ipv4
            elif key == "malicious_ipv6":
                dup_set = self.duplicate_malicious_set_ipv6
            if seed.ip in dup_set:
                self.log(f"Duplicate for {seed.ip} already logged in {key}.")
                return
            dup_set.add(seed.ip)
        report_date = datetime.now(timezone.utc).isoformat()
        comment = self.comment_template.format(ip=seed.ip, discovered_url=seed.get_url(), verdict=seed.source_type)
        line = f'{seed.ip},"{seed.source_type}",{report_date},"{comment}"\n'
        self.write_duplicate_line(key, line)
        self.log(f"Duplicate recorded for {seed.ip} in duplicate file {key}.")

    def run_scan(self):
        self.log("Loading definitions...")
        self.my_public_ip = self.get_my_public_ip()
        seeds = self.load_seeds()
        if not seeds:
            self.log("No seed IP addresses found in the seed files.")
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

    def process_seed(self, seed):
        if self.cancelled:
            return
        with self.lock:
            if seed.ip in self.visited_ips:
                self.log(f"Skipping duplicate processing for {seed.ip}.")
                return
            self.visited_ips.add(seed.ip)
        category = seed.source_type.lower().strip()
        if category.startswith("benign"):
            if self.allow_auto_verdict:
                seed_verdict = "benign (auto verdict 2)" if self.is_active_and_static(seed.ip, seed.port) else "benign (auto verdict 3)"
            else:
                seed_verdict = seed.source_type
        else:
            seed_verdict = seed.source_type
        self.log(f"Processing: {seed.get_url()} (Category: {category})")
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
        report_date = datetime.now(timezone.utc).isoformat()
        # Optimization: If the final URL's hostname (normalized) starts with the seed IP, skip writing to main output.
        parsed_url = urlparse(final_url)
        host = parsed_url.hostname
        if host:
            host = host.lower().strip()
        if host and host.startswith(seed.ip):
            self.log(f"Skipping output for {seed.ip} because final URL hostname '{host}' matches the source IP.")
            main_output_written = True
        else:
            main_output_written = False

        if not main_output_written:
            # Determine output key based on category and IP version.
            if category.startswith("benign"):
                out_key = "whitelist_" + seed.version
            elif category == "phishing":
                out_key = "phishing_" + seed.version
            elif category == "ddos":
                out_key = "ddos_" + seed.version
            elif category == "malicious":
                out_key = "malicious_" + seed.version
            else:
                out_key = "other"
            with self.lock:
                output_already_done = (seed.ip in self.output_ips.get(out_key, set())) if out_key != "other" else False
            if not output_already_done:
                if category.startswith("benign"):
                    comment = self.comment_template.format(ip=seed.ip, discovered_url=final_url, verdict=seed_verdict)
                    line = f'{seed.ip},"{final_url}",{report_date},"{comment}"\n'
                    self.write_whitelist_line(line)
                    with self.lock:
                        self.output_ips[out_key].add(seed.ip)
                    self.log(f"Whitelist output written for {seed.ip}.")
                else:
                    if category == "malicious":
                        category_label = self.settings.get("CategoryMalicious", "20")
                    elif category == "ddos":
                        category_label = self.settings.get("CategoryDDoS", "18")
                    elif category == "phishing":
                        category_label = self.settings.get("CategoryPhishing", "7")
                    else:
                        category_label = ""
                    comment = self.comment_template.format(ip=seed.ip, discovered_url=final_url, verdict=seed.source_type)
                    line = f'{seed.ip},"{category_label}",{report_date},"{comment}"\n'
                    self.write_bulk_line(line)
                    with self.lock:
                        self.output_ips[out_key].add(seed.ip)
                    self.log(f"Bulk output written for {seed.ip}.")
            else:
                duplicate_allowed = False
                if out_key == "whitelist_ipv4":
                    duplicate_allowed = self.settings.get("AllowDuplicateWhitelistIPv4", True)
                elif out_key == "whitelist_ipv6":
                    duplicate_allowed = self.settings.get("AllowDuplicateWhitelistIPv6", True)
                elif out_key == "phishing_ipv4":
                    duplicate_allowed = self.settings.get("AllowDuplicatePhishingIPv4", True)
                elif out_key == "phishing_ipv6":
                    duplicate_allowed = self.settings.get("AllowDuplicatePhishingIPv6", True)
                elif out_key == "ddos_ipv4":
                    duplicate_allowed = self.settings.get("AllowDuplicateDDoSIPv4", True)
                elif out_key == "ddos_ipv6":
                    duplicate_allowed = self.settings.get("AllowDuplicateDDoSIPv6", True)
                elif out_key == "malicious_ipv4":
                    duplicate_allowed = self.settings.get("AllowDuplicateMaliciousIPv4", True)
                elif out_key == "malicious_ipv6":
                    duplicate_allowed = self.settings.get("AllowDuplicateMaliciousIPv6", True)
                if duplicate_allowed:
                    self.log(f"Duplicate for {seed.ip} already output. Logging duplicate.")
                    self.handle_duplicate(category, seed)
                else:
                    self.log(f"Duplicate for {seed.ip} already output. Skipping duplicate.")
        else:
            self.log(f"Main output for {seed.ip} skipped due to optimization check.")

        # Process discovered IPs from page content.
        for ip, port, ip_version in self.extract_ip_and_port(content):
            if self.my_public_ip and ip == self.my_public_ip:
                self.log(f"Skipping my own public IP: {ip}")
                continue
            final_hostname = urlparse(final_url).hostname
            if ip == seed.ip or (final_hostname and ip == final_hostname):
                self.log(f"Skipping discovered IP {ip} because it matches the source.")
                continue
            with self.lock:
                if ip in self.visited_ips:
                    self.log(f"Skipping discovered IP {ip} because it was already processed.")
                    continue
                self.total_seeds += 1
            if category.startswith("benign"):
                new_source_type = seed_verdict
            else:
                new_source_type = "benign (auto verdict 1)" if not self.is_active_and_static(ip, port) else seed.source_type
            new_seed = Seed(ip, new_source_type, ip_version, port=port, is_input=False)
            self.log(f"Recursively processing new seed: {new_seed.get_url()}")
            self.threadpool.start(SeedRunnable(new_seed, self))
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
            self.failure.emit(f"Could not determine public IP: {e}")
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
        def add_file(file, source_type, version):
            if file not in file_category_mapping:
                file_category_mapping[file] = []
            file_category_mapping[file].append((source_type, version))
        for file in [x.strip() for x in self.settings.get("WhiteListFilesIPv6", "").split(",") if x.strip()]:
            add_file(file, "benign", "ipv6")
        for file in [x.strip() for x in self.settings.get("WhiteListFilesIPv4", "").split(",") if x.strip()]:
            add_file(file, "benign", "ipv4")
        for file in [x.strip() for x in self.settings.get("PhishingFilesIPv6", "").split(",") if x.strip()]:
            add_file(file, "phishing", "ipv6")
        for file in [x.strip() for x in self.settings.get("PhishingFilesIPv4", "").split(",") if x.strip()]:
            add_file(file, "phishing", "ipv4")
        for file in [x.strip() for x in self.settings.get("DDoSFilesIPv6", "").split(",") if x.strip()]:
            add_file(file, "ddos", "ipv6")
        for file in [x.strip() for x in self.settings.get("DDoSFilesIPv4", "").split(",") if x.strip()]:
            add_file(file, "ddos", "ipv4")
        for file in [x.strip() for x in self.settings.get("MalwareFilesIPv6", "").split(",") if x.strip()]:
            add_file(file, "malicious", "ipv6")
        for file in [x.strip() for x in self.settings.get("MalwareFilesIPv4", "").split(",") if x.strip()]:
            add_file(file, "malicious", "ipv4")
        results = {}
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_file = {
                executor.submit(self.load_lines, file): file
                for file in file_category_mapping
            }
            for future in concurrent.futures.as_completed(future_to_file):
                file = future_to_file[future]
                try:
                    ips = future.result()
                except Exception as exc:
                    self.log(f"Error loading file {file}: {exc}")
                    ips = []
                results[file] = ips
        for file, ips in results.items():
            for source_type, version in file_category_mapping[file]:
                for ip in ips:
                    if ip not in loaded_ips:
                        seeds.append(Seed(ip, source_type, version, is_input=True))
                        loaded_ips.add(ip)
        self.log(f"Total valid seeds loaded: {len(seeds)}")
        return seeds

    def pause(self):
        self.pause_event.clear()
        self.log("Scan paused.")

    def resume(self):
        self.pause_event.set()
        self.log("Scan resumed.")

# -----------------------------
# MainWindow: Settings GUI with duplicate allowance fields
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
        self.fields = {}
        def add_field(label_text, key, default=""):
            nonlocal row
            lbl = QLabel(label_text)
            le = QLineEdit(str(default))
            settings_layout.addWidget(lbl, row, 0)
            settings_layout.addWidget(le, row, 1)
            self.fields[key] = le
            row += 1
        # Basic settings
        add_field("Max Threads:", "MaxThreads", 1000)
        add_field("CsvMaxLines:", "CsvMaxLines", 10000)
        add_field("CsvMaxSize (bytes):", "CsvMaxSize", 2097152)
        add_field("Bulk Report File:", "OutputFile", default_bulk)
        add_field("Whitelist Report File:", "WhiteListOutputFile", default_whitelist)
        add_field("Category Malicious:", "CategoryMalicious", "20")
        add_field("Category Phishing:", "CategoryPhishing", "7")
        add_field("Category DDoS:", "CategoryDDoS", "18")
        add_field("Comment Template:", "CommentTemplate", 
                  "Related with ip address detected by heuristics of https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine (Source IP: {ip}, Discovered URL: {discovered_url}, Verdict: {verdict})")
        add_field("MalwareFilesIPv6 (comma-separated):", "MalwareFilesIPv6", "website\\IPv6Malware.txt")
        add_field("MalwareFilesIPv4 (comma-separated):", "MalwareFilesIPv4", "website\\IPv4Malware.txt")
        add_field("DDoSFilesIPv6 (comma-separated):", "DDoSFilesIPv6", "")
        add_field("DDoSFilesIPv4 (comma-separated):", "DDoSFilesIPv4", "website\\IPv4DDoS.txt")
        add_field("PhishingFilesIPv6 (comma-separated):", "PhishingFilesIPv6", "")
        add_field("PhishingFilesIPv4 (comma-separated):", "PhishingFilesIPv4", "website\\IPv4PhishingActive.txt, website\\IPv4PhishingInActive.txt")
        add_field("WhiteListFilesIPv6 (comma-separated):", "WhiteListFilesIPv6", "website\\IPv6WhiteList.txt")
        add_field("WhiteListFilesIPv4 (comma-separated):", "WhiteListFilesIPv4", "website\\IPv4WhiteList.txt")
        add_field("WhiteList Path IPv4:", "WhiteListPathIPv4", "website\\IPv4WhiteList.txt")
        add_field("WhiteList Path IPv6:", "WhiteListPathIPv6", "website\\IPv6WhiteList.txt")
        add_field("Phishing Path IPv4:", "PhishingPathIPv4", "website\\IPv4Phishing.txt")
        add_field("Phishing Path IPv6:", "PhishingPathIPv6", "website\\IPv6Phishing.txt")
        add_field("DDoS Path IPv4:", "DDoSPathIPv4", "website\\IPv4DDoS.txt")
        add_field("DDoS Path IPv6:", "DDoSPathIPv6", "website\\IPv6DDoS.txt")
        add_field("Malware Path IPv4:", "MalwarePathIPv4", "website\\IPv4Malware.txt")
        add_field("Malware Path IPv6:", "MalwarePathIPv6", "website\\IPv6Malware.txt")
        # Duplicate allowance fields (default true)
        add_field("Allow Duplicate Whitelist IPv4 (true/false):", "AllowDuplicateWhitelistIPv4", "true")
        add_field("Allow Duplicate Whitelist IPv6 (true/false):", "AllowDuplicateWhitelistIPv6", "true")
        add_field("Allow Duplicate Phishing IPv4 (true/false):", "AllowDuplicatePhishingIPv4", "true")
        add_field("Allow Duplicate Phishing IPv6 (true/false):", "AllowDuplicatePhishingIPv6", "true")
        add_field("Allow Duplicate DDoS IPv4 (true/false):", "AllowDuplicateDDoSIPv4", "true")
        add_field("Allow Duplicate DDoS IPv6 (true/false):", "AllowDuplicateDDoSIPv6", "true")
        add_field("Allow Duplicate Malicious IPv4 (true/false):", "AllowDuplicateMaliciousIPv4", "true")
        add_field("Allow Duplicate Malicious IPv6 (true/false):", "AllowDuplicateMaliciousIPv6", "true")
        # Duplicate file path fields
        add_field("Duplicate Whitelist File IPv4:", "DuplicateWhitelistFileIPv4", "output\\whitelist_ipv4_duplicates.csv")
        add_field("Duplicate Whitelist File IPv6:", "DuplicateWhitelistFileIPv6", "output\\whitelist_ipv6_duplicates.csv")
        add_field("Duplicate Phishing File IPv4:", "DuplicatePhishingFileIPv4", "output\\phishing_ipv4_duplicates.csv")
        add_field("Duplicate Phishing File IPv6:", "DuplicatePhishingFileIPv6", "output\\phishing_ipv6_duplicates.csv")
        add_field("Duplicate DDoS File IPv4:", "DuplicateDDoSFileIPv4", "output\\ddos_ipv4_duplicates.csv")
        add_field("Duplicate DDoS File IPv6:", "DuplicateDDoSFileIPv6", "output\\ddos_ipv6_duplicates.csv")
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
                     "AllowDuplicateDDoSIPv4", "AllowDuplicateDDoSIPv6",
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

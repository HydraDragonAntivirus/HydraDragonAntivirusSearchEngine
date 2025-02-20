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

from PySide6.QtCore import QObject, Signal, QThread
from PySide6.QtGui import QIcon
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
    QTextEdit,  # For multi-line logging
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
# Seed class
# -----------------------------
class Seed:
    def __init__(self, ip, source_type, version, port=None, depth=0, source_url=None):
        self.ip = ip.lower()
        # source_type: "malicious", "ddos", "phishing", or "benign"
        self.source_type = source_type  
        self.version = version  # "ipv4" or "ipv6"
        self.port = port        # Port number if available
        self.depth = depth
        self.source_url = source_url  # URL where this IP was found

    def get_url(self):
        return f"http://{self.ip}:{self.port}" if self.port else f"http://{self.ip}"

# -----------------------------
# ScannerWorker using settings
# -----------------------------
class ScannerWorker(QObject):
    log_signal = Signal(str)
    progress_signal = Signal(int, int)  # processed, total
    finished_signal = Signal()
    failure = Signal(str)

    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.max_depth = int(settings.get("MaxDepth", 10))
        self.max_workers = int(settings.get("MaxThreads", 100))
        # User-defined CsvMaxLines; if above 10k, enforce 10k per file.
        self.user_csv_max_lines = int(settings.get("CsvMaxLines", 10000))
        self.csv_max_lines = self.user_csv_max_lines if self.user_csv_max_lines <= 10000 else 10000
        # User-defined CsvMaxSize (in bytes)
        self.csv_max_size = int(settings.get("CsvMaxSize", 2097152))
        if self.user_csv_max_lines > 10000:
            self.log(f"CsvMaxLines set to {self.user_csv_max_lines} but will be enforced as 10,000 per file due to AbuseIPDB limits.")
        self.comment_template = settings.get("CommentTemplate", "")
        self.scan_known_active = settings.get("ScanKnownActive", False)
        self.allow_auto_verdict = settings.get("AllowAutoVerdict", True)
        # File lists (comma-separated strings converted to lists)
        self.malware_files_ipv4 = [x.strip() for x in settings.get("MalwareFilesIPv4", "").split(",") if x.strip()]
        self.malware_files_ipv6 = [x.strip() for x in settings.get("MalwareFilesIPv6", "").split(",") if x.strip()]
        self.ddos_files_ipv4 = [x.strip() for x in settings.get("DDoSFilesIPv4", "").split(",") if x.strip()]
        self.ddos_files_ipv6 = [x.strip() for x in settings.get("DDoSFilesIPv6", "").split(",") if x.strip()]
        self.phishing_files_ipv4 = [x.strip() for x in settings.get("PhishingFilesIPv4", "").split(",") if x.strip()]
        self.phishing_files_ipv6 = [x.strip() for x in settings.get("PhishingFilesIPv6", "").split(",") if x.strip()]
        self.whitelist_files_ipv4 = [x.strip() for x in settings.get("WhiteListFilesIPv4", "").split(",") if x.strip()]
        self.whitelist_files_ipv6 = [x.strip() for x in settings.get("WhiteListFilesIPv6", "").split(",") if x.strip()]
        # Paths
        self.malware_path = settings.get("MalwarePath", "")
        self.ddos_path = settings.get("DDoSPath", "")
        self.phishing_path = settings.get("PhishingPath", "")
        self.whitelist_path = settings.get("WhiteListPath", "")
        # Categories
        self.cat_malicious = settings.get("CategoryMalicious", "20")
        self.cat_ddos = settings.get("CategoryDDoS", "18")
        self.cat_phishing = settings.get("CategoryPhishing", "7")
        # Output filenames
        self.out_bulk_csv = settings.get("OutputFile", default_bulk)
        self.out_whitelist_csv = settings.get("WhiteListOutputFile", default_whitelist)

        self.my_public_ip = None
        self.all_known_ips = set()
        self.processed_depths = {} 
        self.processed_count = 0
        self.total_seeds = 0
        self.lock = threading.Lock()
        self.cancelled = False

        # CSV splitting variables
        self.bulk_file_index = 0
        self.whitelist_file_index = 0
        self.bulk_line_count = 0
        self.whitelist_line_count = 0
        self.bulk_file = None
        self.whitelist_file = None
        # Track current file sizes in bytes
        self.bulk_file_size = 0
        self.whitelist_file_size = 0

        # Pause/Resume event; set means "not paused"
        self.pause_event = threading.Event()
        self.pause_event.set()

    def log(self, message):
        self.log_signal.emit(message)
        logging.info(message)

    def update_progress(self):
        self.progress_signal.emit(self.processed_count, self.total_seeds)
 
    def open_csv_files(self):
        # Create directories for output files if they don't exist.
        bulk_dir = os.path.dirname(self.out_bulk_csv)
        if bulk_dir and not os.path.exists(bulk_dir):
            os.makedirs(bulk_dir, exist_ok=True)
        whitelist_dir = os.path.dirname(self.out_whitelist_csv)
        if whitelist_dir and not os.path.exists(whitelist_dir):
            os.makedirs(whitelist_dir, exist_ok=True)
        self.bulk_file_index = 0
        self.whitelist_file_index = 0
        header = "IP,Categories,ReportDate,Comment\n"
        self.bulk_line_count = 1  # header counts as first line
        self.whitelist_line_count = 1
        self.bulk_file = open(self.out_bulk_csv, "w", encoding="utf-8")
        self.whitelist_file = open(self.out_whitelist_csv, "w", encoding="utf-8")
        self.bulk_file.write(header)
        self.whitelist_file.write(header)
        self.bulk_file.flush()
        self.whitelist_file.flush()
        # Initialize size counters from header
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
            # Rotate file if line count or file size limit is reached
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
                self.log(f"Bulk file size or line limit reached; switching to file: {new_filename}")
            self.bulk_file.write(line)
            self.bulk_file.flush()
            self.bulk_line_count += 1
            self.bulk_file_size += line_bytes

    def write_whitelist_line(self, line):
        with self.lock:
            # Simply write the line without checking for csv_max_lines
            self.whitelist_file.write(line)
            self.whitelist_file.flush()
            self.whitelist_line_count += 1
            self.whitelist_file_size += len(line.encode("utf-8"))

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
        self.log(f"Enqueued initial seeds: {len(seeds)}")
        self.open_csv_files()

        seed_queue = Queue()
        for seed in seeds:
            seed_queue.put(seed)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for _ in range(self.max_workers):
                executor.submit(self.worker_thread, seed_queue)
            seed_queue.join()

        self.close_csv_files()
        self.log("Scan completed.")
        self.finished_signal.emit()

    def worker_thread(self, seed_queue):
        while not self.cancelled:
            self.pause_event.wait()
            try:
                seed = seed_queue.get(timeout=5)
            except Empty:
                break
            self.process_seed_worker(seed, seed_queue)
            seed_queue.task_done()

    def process_seed_worker(self, seed, seed_queue):
        if self.cancelled:
            return
        with self.lock:
            # Allow re-scanning the same IP if the new depth is higher.
            if seed.ip in self.processed_depths and self.processed_depths[seed.ip] >= seed.depth:
                return
            self.processed_depths[seed.ip] = seed.depth

        self.log(f"Visiting (depth {seed.depth}): {seed.get_url()}")
        try:
            response = requests.get(seed.get_url(), timeout=10)
            final_url = response.url
        except Exception as e:
            self.log(f"Error visiting {seed.get_url()}: {e}")
            self.failure.emit(f"Error visiting {seed.get_url()}: {e}")
            with self.lock:
                self.processed_count += 1
                self.update_progress()
            return

        if response.status_code != 200:
            self.log(f"Non-OK status {response.status_code} for {seed.get_url()}")
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

        self.log(f"Visited: {seed.get_url()}")

        # If the seed's current depth is below the maximum, scan its content.
        if seed.depth < self.max_depth:
            found_ips = self.extract_ip_and_port(content)
            for ip, port, ip_version in found_ips:
                if self.cancelled:
                    return
                if self.my_public_ip and ip == self.my_public_ip:
                    self.log(f"Skipping my own public IP: {ip}")
                    continue

                new_depth = seed.depth + 1
                with self.lock:
                    # Only add if this IP hasn't been scanned at a higher or equal depth.
                    if ip in self.processed_depths and self.processed_depths[ip] >= new_depth:
                        continue
                    self.processed_depths[ip] = new_depth

                # Determine the new source type based on active/static check.
                if seed.source_type.lower() == "benign":
                    new_source_type = "benign (auto verdict 2)" if self.is_active_and_static(ip, port) else "benign (auto verdict 3)"
                else:
                    new_source_type = "benign (auto verdict 1)" if not self.is_active_and_static(ip, port) else seed.source_type

                report_date = datetime.now(timezone.utc).isoformat()
                new_ip_url = f"http://{ip}" + (f":{port}" if port else "")
                comment = self.comment_template.format(
                    ip=seed.ip,
                    source_url=final_url,
                    discovered_url=new_ip_url,
                    verdict=new_source_type,
                    depth=new_depth
                )[:1024]

                if new_source_type.lower().startswith("benign"):
                    category = ""
                    self.write_whitelist_line(f'{ip},"{category}",{report_date},"{comment}"\n')
                else:
                    if new_source_type.lower() == "malicious":
                        category = self.cat_malicious
                    elif new_source_type.lower() == "ddos":
                        category = self.cat_ddos
                    elif new_source_type.lower() == "phishing":
                        category = self.cat_phishing
                    else:
                        category = ""
                    self.write_bulk_line(f'{ip},"{category}",{report_date},"{comment}"\n')

                new_seed = Seed(ip, new_source_type, ip_version, port=port, depth=new_depth, source_url=final_url)
                seed_queue.put(new_seed)
                with self.lock:
                     self.total_seeds += 1
                self.log(f"Enqueued new seed: {new_seed.get_url()} with depth {new_seed.depth}")

        with self.lock:
            self.processed_count += 1
            self.update_progress()

        # Re-enqueue the current seed for a re-scan with increased depth (if we haven't reached max depth).
        if seed.depth < self.max_depth:
            new_seed = Seed(seed.ip, seed.source_type, seed.version, port=seed.port, depth=seed.depth + 1, source_url=final_url)
            seed_queue.put(new_seed)
            with self.lock:
                 self.total_seeds += 1
            self.log(f"Re-enqueued {new_seed.get_url()} for re-scan with increased depth {new_seed.depth}")

    def get_my_public_ip(self):
        try:
            response = requests.get("https://api.ipify.org", timeout=5)
            ip = response.text.strip()
            self.log(f"My public IP is {ip}")
            return ip
        except Exception as e:
            self.log(f"Could not determine public IP: {e}")
            self.failure.emit(f"Could not determine public IP: {e}")
            return None

    def is_active_and_static(self, ip, port, timeout=5):
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

        # Order: whitelist (IPv6 then IPv4), then phishing (IPv6 then IPv4),
        # then ddos (IPv6 then IPv4), then malicious (IPv6 then IPv4)
        for file in self.whitelist_files_ipv6:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "benign", "ipv6", depth=0))
        for file in self.whitelist_files_ipv4:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "benign", "ipv4", depth=0))
        for file in self.phishing_files_ipv6:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "phishing", "ipv6", depth=0))
        for file in self.phishing_files_ipv4:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "phishing", "ipv4", depth=0))
        for file in self.ddos_files_ipv6:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "ddos", "ipv6", depth=0))
        for file in self.ddos_files_ipv4:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "ddos", "ipv4", depth=0))
        for file in self.malware_files_ipv6:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "malicious", "ipv6", depth=0))
        for file in self.malware_files_ipv4:
            for ip in get_ips_from_file(file):
                seeds.append(Seed(ip, "malicious", "ipv4", depth=0))

        self.all_known_ips = set()
        for file_list in [self.whitelist_files_ipv6, self.whitelist_files_ipv4,
                          self.phishing_files_ipv6, self.phishing_files_ipv4,
                          self.ddos_files_ipv6, self.ddos_files_ipv4,
                          self.malware_files_ipv6, self.malware_files_ipv4]:
            for file in file_list:
                self.all_known_ips |= get_ips_from_file(file)
        self.log(f"Total valid seeds loaded: {len(seeds)}")
        self.log(f"Total known IPs: {len(self.all_known_ips)}")
        return seeds

    # Methods to control pausing/resuming the scan
    def pause(self):
        self.pause_event.clear()
        self.log("Scan paused.")

    def resume(self):
        self.pause_event.set()
        self.log("Scan resumed.")

# -----------------------------
# MainWindow: Manual Settings GUI
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

        # Settings Group (manually edited fields)
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

        add_field("Max Depth:", "MaxDepth", 10)
        add_field("Max Threads:", "MaxThreads", 100)
        add_field("CsvMaxLines:", "CsvMaxLines", 10000)
        add_field("CsvMaxSize (bytes):", "CsvMaxSize", 2097152)
        add_field("Bulk Report File:", "OutputFile", default_bulk)
        add_field("Whitelist Report File:", "WhiteListOutputFile", default_whitelist)
        add_field("Category Malicious:", "CategoryMalicious", "20")
        add_field("Category Phishing:", "CategoryPhishing", "7")
        add_field("Category DDoS:", "CategoryDDoS", "18")
        add_field("Comment Template:", "CommentTemplate", "Related with ip address detected by heuristics of https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine (Source IP: {ip}, Source URL: {source_url}, Discovered URL: {discovered_url}, Verdict: {verdict}, Depth: {depth})")
        add_field("MalwareFilesIPv6 (comma-separated):", "MalwareFilesIPv6", "website\\IPv6Malware.txt")
        add_field("MalwareFilesIPv4 (comma-separated):", "MalwareFilesIPv4", "website\\IPv4Malware.txt")
        add_field("DDoSFilesIPv6 (comma-separated):", "DDoSFilesIPv6", "")
        add_field("DDoSFilesIPv4 (comma-separated):", "DDoSFilesIPv4", "website\\IPv4DDoS.txt")
        add_field("PhishingFilesIPv6 (comma-separated):", "PhishingFilesIPv6", "")
        add_field("PhishingFilesIPv4 (comma-separated):", "PhishingFilesIPv4", "website\\IPv4PhishingActive.txt, website\\IPv4PhishingInActive.txt")
        add_field("WhiteListFilesIPv6 (comma-separated):", "WhiteListFilesIPv6", "website\\IPv6WhiteList.txt")
        add_field("WhiteListFilesIPv4 (comma-separated):", "WhiteListFilesIPv4", "website\\IPv4WhiteList.txt")
        add_field("MalwarePath:", "MalwarePath", "website")
        add_field("DDoSPath:", "DDoSPath", "website")
        add_field("PhishingPath:", "PhishingPath", "website")
        add_field("WhiteListPath:", "WhiteListPath", "website")
        add_field("ScanKnownActive (true/false):", "ScanKnownActive", "false")
        add_field("AllowAutoVerdict (true/false):", "AllowAutoVerdict", "true")

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

        # Two buttons: one to start/stop the scan, one to pause/resume.
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

        # Use QTextEdit for logging
        main_layout.addWidget(QLabel("Log:"))
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        main_layout.addWidget(self.log_text)

    def get_settings_from_fields(self):
        settings = {}
        for key, le in self.fields.items():
            value = le.text().strip()
            if key in ("MaxDepth", "MaxThreads", "CsvMaxLines", "CsvMaxSize"):
                try:
                    value = int(value)
                except:
                    value = 0
            if key in ("ScanKnownActive", "AllowAutoVerdict"):
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
        self.progress_bar.setFormat(f"{processed}/{total} ({percent:.0f}%)")

    def scan_finished(self):
        self.append_log("Scan finished.")
        self.start_stop_button.setText("Start Scan")
        self.pause_button.setVisible(False)
        self.is_scanning = False
        self.is_paused = False
        if self.thread:
            self.thread.quit()
            self.thread.wait()

def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(antivirus_style)
    window = MainWindow()
    window.resize(800, 600)
    window.show()
    sys.exit(app.exec())

# -----------------------------
# Main entry point
# -----------------------------
if __name__ == "__main__":
    main()

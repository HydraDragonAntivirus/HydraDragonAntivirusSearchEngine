import os
import re
import sys
import json
import ipaddress
import threading
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty

from PySide6.QtCore import QObject, Signal, QThread
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QProgressBar,
    QFileDialog,
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

QLabel {
    color: #e0e0e0;
}

QFileDialog {
    background-color: #2b2b2b;
    color: #e0e0e0;
}

QListWidget {
    background-color: #3c3c3c;
    color: #e0e0e0;
    border: 1px solid #5a5a5a;
}

QListWidget::item {
    padding: 4px;
}

QListWidget::item:selected {
    background-color: #007bff;
    color: white;
}

QCheckBox {
    color: #e0e0e0;
}

QComboBox {
    background-color: #3c3c3c;
    color: #e0e0e0;
    border: 1px solid #5a5a5a;
    padding: 2px 8px;
    border-radius: 4px;
    min-width: 80px;
}

QDialog {
    background-color: #2b2b2b;
    color: #e0e0e0;
}

QDialogButtonBox {
    background-color: #2b2b2b;
}
"""

# -----------------------------
# Seed class
# -----------------------------
class Seed:
    def __init__(self, ip, source_type, version, port=None, depth=0, source_url=None):
        self.ip = ip.lower()
        # source_type can be "malicious", "ddos", "phishing", or "benign"
        self.source_type = source_type  
        self.version = version  # "ipv4" or "ipv6"
        self.port = port        # Port number if available
        self.depth = depth
        self.source_url = source_url  # URL where this IP was found

    def get_url(self):
        return f"http://{self.ip}:{self.port}" if self.port else f"http://{self.ip}"

# -----------------------------
# ScannerWorker using settings from JSON
# -----------------------------
class ScannerWorker(QObject):
    log_signal = Signal(str)
    progress_signal = Signal(int, int)  # processed, total
    finished_signal = Signal()
    failure = Signal(str)

    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.max_depth = settings.get("MaxDepth", 10)
        self.max_workers = settings.get("MaxThreads", 20)
        self.csv_max_lines = settings.get("CsvMaxLines", 10000)
        self.csv_max_size = settings.get("CsvMaxSize", 2097152)
        self.comment_template = settings.get("CommentTemplate", "")
        self.scan_known_active = settings.get("ScanKnownActive", False)
        self.allow_auto_verdict = settings.get("AllowAutoVerdict", True)
        # File paths for seed lists
        self.malware_files_ipv4 = settings.get("MalwareFilesIPv4", [])
        self.malware_files_ipv6 = settings.get("MalwareFilesIPv6", [])
        self.ddos_files_ipv4 = settings.get("DDoSFilesIPv4", [])
        self.ddos_files_ipv6 = settings.get("DDoSFilesIPv6", [])
        self.phishing_files_ipv4 = settings.get("PhishingFilesIPv4", [])
        self.phishing_files_ipv6 = settings.get("PhishingFilesIPv6", [])
        self.whitelist_files_ipv4 = settings.get("WhiteListFilesIPv4", [])
        self.whitelist_files_ipv6 = settings.get("WhiteListFilesIPv6", [])
        # For this example, we use the path settings (all set to "website" in your JSON)
        self.malware_path = settings.get("MalwarePath", "")
        self.ddos_path = settings.get("DDoSPath", "")
        self.phishing_path = settings.get("PhishingPath", "")
        self.whitelist_path = settings.get("WhiteListPath", "")
        # Output filenames (could be extended to be configurable too)
        self.out_malicious_filename    = "NewDiscoveredIPs_malicious.csv"   # CategoryMalicious: settings["CategoryMalicious"]
        self.out_ddos_filename         = "NewDiscoveredIPs_ddos.csv"        # CategoryDDoS: settings["CategoryDDoS"]
        self.out_phishing_filename     = "NewDiscoveredIPs_phishing.csv"    # CategoryPhishing: settings["CategoryPhishing"]
        self.out_benign_filename       = "NewDiscoveredIPs_benign.csv"      
        self.out_benign_auto1_filename = "NewDiscoveredIPs_benign_auto_verdict1.csv"
        self.out_benign_auto2_filename = "NewDiscoveredIPs_benign_auto_verdict2.csv"
        self.out_benign_auto3_filename = "NewDiscoveredIPs_benign_auto_verdict3.csv"
        
        self.my_public_ip = None
        self.all_known_ips = set()
        self.processed_set = set()
        self.processed_count = 0
        self.total_seeds = 0
        self.lock = threading.Lock()
        self.cancelled = False

    def log(self, message):
        self.log_signal.emit(message)
        print(message)

    def update_progress(self):
        self.progress_signal.emit(self.processed_count, self.total_seeds)

    def run_scan(self):
        self.log("Starting scan...")
        self.my_public_ip = self.get_my_public_ip()
        seeds = self.load_seeds()
        if not seeds:
            self.log("No seed IP addresses found in the seed files.")
            self.finished_signal.emit()
            return

        self.total_seeds = len(seeds)
        self.log(f"Enqueued initial seeds: {len(seeds)}")

        # Open CSV output files
        out_malicious    = open(self.out_malicious_filename, "w", encoding="utf-8")
        out_ddos         = open(self.out_ddos_filename, "w", encoding="utf-8")
        out_phishing     = open(self.out_phishing_filename, "w", encoding="utf-8")
        out_benign       = open(self.out_benign_filename, "w", encoding="utf-8")
        out_benign_auto1 = open(self.out_benign_auto1_filename, "w", encoding="utf-8")
        out_benign_auto2 = open(self.out_benign_auto2_filename, "w", encoding="utf-8")
        out_benign_auto3 = open(self.out_benign_auto3_filename, "w", encoding="utf-8")

        header = "IP,Categories,ReportDate,Comment\n"
        for f in [out_malicious, out_ddos, out_phishing, out_benign, out_benign_auto1, out_benign_auto2, out_benign_auto3]:
            f.write(header)

        seed_queue = Queue()
        for seed in seeds:
            seed_queue.put(seed)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for _ in range(self.max_workers):
                executor.submit(
                    self.worker_thread,
                    seed_queue,
                    out_malicious,
                    out_ddos,
                    out_phishing,
                    out_benign,
                    out_benign_auto1,
                    out_benign_auto2,
                    out_benign_auto3,
                )
            seed_queue.join()

        for f in [out_malicious, out_ddos, out_phishing, out_benign, out_benign_auto1, out_benign_auto2, out_benign_auto3]:
            f.close()

        self.log("Scan completed.")
        self.finished_signal.emit()

    def worker_thread(self, seed_queue, out_malicious, out_ddos, out_phishing, out_benign, out_benign_auto1, out_benign_auto2, out_benign_auto3):
        while not self.cancelled:
            try:
                seed = seed_queue.get(timeout=5)
            except Empty:
                break
            self.process_seed_worker(seed, seed_queue,
                                     out_malicious, out_ddos, out_phishing, out_benign,
                                     out_benign_auto1, out_benign_auto2, out_benign_auto3)
            seed_queue.task_done()

    def process_seed_worker(self, seed, seed_queue,
                              out_malicious, out_ddos, out_phishing, out_benign,
                              out_benign_auto1, out_benign_auto2, out_benign_auto3):
        if self.cancelled:
            return
        with self.lock:
            if seed.ip in self.processed_set:
                return
            self.processed_set.add(seed.ip)
        url = seed.get_url()
        self.log(f"Visiting (depth {seed.depth}): {url}")
        try:
            response = requests.get(url, timeout=10)
            final_url = response.url
        except Exception as e:
            self.log(f"Error visiting {url}: {e}")
            self.failure.emit(f"Error visiting {url}: {e}")
            return
        if response.status_code != 200:
            self.log(f"Non-OK status {response.status_code} for {url}")
            return
        content = response.text
        if not content:
            self.log(f"No content from {url}")
            return
        self.log(f"Visited: {url}")

        if seed.depth < self.max_depth:
            found_ips = self.extract_ip_and_port(content)
            for ip, port, ip_version in found_ips:
                if self.cancelled:
                    return
                if self.my_public_ip and ip == self.my_public_ip:
                    self.log(f"Skipping my own public IP: {ip}")
                    continue
                with self.lock:
                    if ip in self.all_known_ips or ip in self.processed_set:
                        continue

                # Apply benign auto verdict logic:
                # - For non-benign seeds (malicious, ddos, phishing): if not active, mark as "benign (auto verdict 1)"
                # - For seeds already benign: if active, mark as "benign (auto verdict 2)", else "benign (auto verdict 3)"
                if seed.source_type.startswith("benign"):
                    if self.is_active_and_static(ip, port):
                        new_source_type = "benign (auto verdict 2)"
                    else:
                        new_source_type = "benign (auto verdict 3)"
                else:
                    if not self.is_active_and_static(ip, port):
                        new_source_type = "benign (auto verdict 1)"
                    else:
                        new_source_type = seed.source_type

                report_date = datetime.now(timezone.utc).isoformat()
                new_ip_url = f"http://{ip}" + (f":{port}" if port else "")
                comment = self.comment_template.format(
                    ip=seed.ip,
                    source_url=final_url,
                    discovered_url=new_ip_url,
                    verdict=new_source_type,
                    depth=seed.depth
                )
                comment = comment[:1024]

                # Determine CSV output file and category code based on new_source_type
                if new_source_type == "malicious":
                    category = self.settings.get("CategoryMalicious", "20")
                    out_file = out_malicious
                elif new_source_type == "ddos":
                    category = self.settings.get("CategoryDDoS", "18")
                    out_file = out_ddos
                elif new_source_type == "phishing":
                    category = self.settings.get("CategoryPhishing", "7")
                    out_file = out_phishing
                elif new_source_type == "benign (auto verdict 1)":
                    category = ""
                    out_file = out_benign_auto1
                elif new_source_type == "benign (auto verdict 2)":
                    category = ""
                    out_file = out_benign_auto2
                elif new_source_type == "benign (auto verdict 3)":
                    category = ""
                    out_file = out_benign_auto3
                elif new_source_type == "benign":
                    category = ""
                    out_file = out_benign
                else:
                    category = ""
                    out_file = out_benign

                csv_line = f'{ip},"{category}",{report_date},"{comment}"\n'
                with self.lock:
                    out_file.write(csv_line)
                    out_file.flush()

                new_seed = Seed(ip, new_source_type, ip_version, port=port, depth=seed.depth + 1, source_url=final_url)
                seed_queue.put(new_seed)
                with self.lock:
                    self.processed_count += 1
                    self.update_progress()

        with self.lock:
            self.processed_count += 1
            self.update_progress()

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
        # Load seeds from each file list in settings
        for file in self.malware_files_ipv4:
            for ip in self.load_lines(file):
                seeds.append(Seed(ip, "malicious", "ipv4", depth=0))
        for file in self.malware_files_ipv6:
            for ip in self.load_lines(file):
                seeds.append(Seed(ip, "malicious", "ipv6", depth=0))
        for file in self.ddos_files_ipv4:
            for ip in self.load_lines(file):
                seeds.append(Seed(ip, "ddos", "ipv4", depth=0))
        for file in self.ddos_files_ipv6:
            for ip in self.load_lines(file):
                seeds.append(Seed(ip, "ddos", "ipv6", depth=0))
        for file in self.phishing_files_ipv4:
            for ip in self.load_lines(file):
                seeds.append(Seed(ip, "phishing", "ipv4", depth=0))
        for file in self.phishing_files_ipv6:
            for ip in self.load_lines(file):
                seeds.append(Seed(ip, "phishing", "ipv6", depth=0))
        for file in self.whitelist_files_ipv4:
            for ip in self.load_lines(file):
                seeds.append(Seed(ip, "benign", "ipv4", depth=0))
        for file in self.whitelist_files_ipv6:
            for ip in self.load_lines(file):
                seeds.append(Seed(ip, "benign", "ipv6", depth=0))
        # Build the set of all known IPs to avoid duplicates
        self.all_known_ips = set()
        for file_list in [self.malware_files_ipv4, self.malware_files_ipv6, self.ddos_files_ipv4, self.ddos_files_ipv6,
                          self.phishing_files_ipv4, self.phishing_files_ipv6, self.whitelist_files_ipv4, self.whitelist_files_ipv6]:
            for file in file_list:
                self.all_known_ips |= self.load_lines(file)
        self.log(f"Total valid seeds loaded: {len(seeds)}")
        self.log(f"Total known IPs: {len(self.all_known_ips)}")
        return seeds

# -----------------------------
# PySide6 GUI with JSON Settings
# -----------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hydra Dragon Antivirus Search Engine")
        self.worker = None
        self.thread = None
        self.settings = None
        self.setup_ui()

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Settings file selection
        settings_layout = QHBoxLayout()
        self.settings_edit = QLineEdit()
        self.settings_edit.setPlaceholderText("Select JSON settings file")
        self.settings_button = QPushButton("Load Settings")
        self.settings_button.clicked.connect(self.load_settings)
        settings_layout.addWidget(QLabel("Settings File:"))
        settings_layout.addWidget(self.settings_edit)
        settings_layout.addWidget(self.settings_button)
        layout.addLayout(settings_layout)

        # Seed folder selection (optional if files are fully specified in settings)
        form_layout = QHBoxLayout()
        self.seed_dir_edit = QLineEdit()
        self.seed_dir_edit.setPlaceholderText("(Optional) Folder for seed files")
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_folder)
        form_layout.addWidget(QLabel("Seed Folder:"))
        form_layout.addWidget(self.seed_dir_edit)
        form_layout.addWidget(self.browse_button)
        layout.addLayout(form_layout)

        # Parameters: Max Depth and Max Threads (overridable via settings)
        form_layout2 = QHBoxLayout()
        self.max_depth_edit = QLineEdit("10")
        self.max_workers_edit = QLineEdit("20")
        form_layout2.addWidget(QLabel("Max Depth:"))
        form_layout2.addWidget(self.max_depth_edit)
        form_layout2.addWidget(QLabel("Max Threads:"))
        form_layout2.addWidget(self.max_workers_edit)
        layout.addLayout(form_layout2)

        # Start/Stop buttons
        btn_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        btn_layout.addWidget(self.start_button)
        btn_layout.addWidget(self.stop_button)
        layout.addLayout(btn_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        # Log text area
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)

    def load_settings(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open JSON Settings File", os.getcwd(), "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    self.settings = json.load(f)
                self.settings_edit.setText(file_path)
                self.append_log("Settings loaded successfully.")
                # Optionally, update UI fields from settings
                self.max_depth_edit.setText(str(self.settings.get("MaxDepth", 10)))
                self.max_workers_edit.setText(str(self.settings.get("MaxThreads", 20)))
            except Exception as e:
                self.append_log(f"Failed to load settings: {e}")

    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Seed Folder", os.getcwd())
        if folder:
            self.seed_dir_edit.setText(folder)

    def start_scan(self):
        if not self.settings:
            self.append_log("Please load a JSON settings file first.")
            return
        # Optionally override settings with UI values
        try:
            self.settings["MaxDepth"] = int(self.max_depth_edit.text())
            self.settings["MaxThreads"] = int(self.max_workers_edit.text())
        except ValueError:
            self.append_log("Max Depth and Max Threads must be integers.")
            return

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.append_log("Starting scan...")

        self.worker = ScannerWorker(self.settings)
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
            self.stop_button.setEnabled(False)

    def append_log(self, message):
        self.log_text.append(message)

    def update_progress(self, processed, total):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(processed)

    def scan_finished(self):
        self.append_log("Scan finished.")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        if self.thread:
            self.thread.quit()
            self.thread.wait()

# -----------------------------
# Main entry point
# -----------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(antivirus_style)
    window = MainWindow()
    window.resize(800, 600)
    window.show()
    sys.exit(app.exec())

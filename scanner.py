import os
import re
import sys
import logging
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty
import threading
import requests
from tqdm import tqdm
from urllib.parse import urlparse
from datetime import datetime, timezone

# Category assignments:
# - Malicious: Use category "20"
CATEGORY_MALICIOUS = "20"
# - Phishing: Use category "7"
CATEGORY_PHISHING = "7"
# - Benign: Empty category (i.e. no category)
CATEGORY_BENIGN = ""

# Determine the script directory and create a log folder and log file path
script_dir = os.getcwd()
log_folder = os.path.join(script_dir, "log")
if not os.path.exists(log_folder):
    os.makedirs(log_folder)
log_file = os.path.join(log_folder, "scanner.log")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file, mode='a', encoding='utf-8')]
)

# Maximum recursion depth
MAX_DEPTH = 10

# Global file handles for CSV outputs (will be set in main)
out_malicious = None
out_phishing = None
out_benign = None
out_benign_auto = None

class Seed:
    def __init__(self, ip, source_type, version, port=None, depth=0, source_url=None):
        self.ip = ip.lower()
        # source_type can be: "malicious", "phishing", or "benign"
        self.source_type = source_type  
        self.version = version          # "ipv4" or "ipv6"
        self.port = port                # Port number if available
        self.depth = depth
        self.source_url = source_url    # URL where this IP was found

    def __repr__(self):
        port_str = f":{self.port}" if self.port else ""
        return f"Seed({self.ip}{port_str}, {self.source_type}, {self.version}, depth={self.depth})"

    def get_url(self):
        """Generate the full URL for this seed."""
        return f"http://{self.ip}:{self.port}" if self.port else f"http://{self.ip}"

def is_valid_ip(ip_string):
    """
    Validate IP address and return its version or None if invalid.
    Also skips private, loopback, link-local, multicast, and reserved addresses.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or \
           ip_obj.is_multicast or ip_obj.is_reserved:
            return None
        return "ipv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "ipv6"
    except ValueError:
        return None

def extract_ip_and_port(text):
    """Extract valid IP addresses and their ports from text."""
    found_ips = []
    # IPv4 pattern: e.g. 192.168.1.1 or 192.168.1.1:8080
    ipv4_pattern = re.compile(
        r'\b(?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::(?P<port>[0-9]{1,5}))?\b'
    )
    # IPv6 with brackets: e.g. [2001:db8::1] or [2001:db8::1]:80
    ipv6_bracket_pattern = re.compile(
        r'\[(?P<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})\](?::(?P<port>[0-9]{1,5}))?'
    )
    # IPv6 without brackets: e.g. 2001:db8::1 (no port info)
    ipv6_pattern = re.compile(
        r'\b(?P<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})\b'
    )

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
    """Load valid IPs from a file (one per line, optionally with port)."""
    s = set()
    if os.path.exists(path):
        with open(path, "r") as f:
            for line in f:
                line = line.strip().lower()
                if ':' in line:
                    ip, _ = line.rsplit(':', 1)
                else:
                    ip = line
                if ip and is_valid_ip(ip):
                    s.add(ip)
    logging.debug(f"Loaded {len(s)} valid IPs from {path}")
    return s

def load_seeds(website_dir):
    seeds = []
    # Load malware and whitelist files
    malware_ipv4 = load_lines(os.path.join(website_dir, "IPv4Malware.txt"))
    malware_ipv6 = load_lines(os.path.join(website_dir, "IPv6Malware.txt"))
    whitelist_ipv4 = load_lines(os.path.join(website_dir, "IPv4WhiteList.txt"))
    whitelist_ipv6 = load_lines(os.path.join(website_dir, "IPv6WhiteList.txt"))
    for ip in malware_ipv4:
        seeds.append(Seed(ip, "malicious", "ipv4", depth=0))
    for ip in malware_ipv6:
        seeds.append(Seed(ip, "malicious", "ipv6", depth=0))
    for ip in whitelist_ipv4:
        seeds.append(Seed(ip, "benign", "ipv4", depth=0))
    for ip in whitelist_ipv6:
        seeds.append(Seed(ip, "benign", "ipv6", depth=0))
    # Load phishing lists (highest priority)
    phishing_ipv4_active = load_lines(os.path.join(website_dir, "IPv4PhishingActive.txt"))
    phishing_ipv4_inactive = load_lines(os.path.join(website_dir, "IPv4PhishingInActive.txt"))
    for ip in phishing_ipv4_active:
        seeds.append(Seed(ip, "phishing", "ipv4", depth=0))
    for ip in phishing_ipv4_inactive:
        seeds.append(Seed(ip, "phishing", "ipv4", depth=0))
    global all_known_ips
    all_known_ips = (malware_ipv4 | malware_ipv6 | whitelist_ipv4 | whitelist_ipv6 |
                     phishing_ipv4_active | phishing_ipv4_inactive)
    logging.debug(f"Total valid seeds loaded: {len(seeds)}")
    logging.debug(f"Total known IPs: {len(all_known_ips)}")
    return seeds

# Global collections to track processed IPs and discovered IPs per type.
all_known_ips = set()
processed_set = set()
new_ips_from_malicious = set()
new_ips_from_phishing = set()
new_ips_from_benign = set()
new_ips_from_benign_auto = set()

class Counter:
    def __init__(self, initial=0):
        self.value = initial
        self.lock = threading.Lock()
        self.progress_bar = None
    def increment(self, amount=1):
        with self.lock:
            self.value += amount
            if self.progress_bar:
                self.progress_bar.update(amount)
    def get(self):
        with self.lock:
            return self.value
    def set_progress_bar(self, pbar):
        self.progress_bar = pbar

tasks_count = Counter(0)
processed_count = Counter(0)

processed_lock = threading.Lock()
output_lock = threading.Lock()

MY_PUBLIC_IP = None
def get_my_public_ip():
    """Determine and return the public IP address of this machine."""
    try:
        response = requests.get("https://api.ipify.org", timeout=5)
        ip = response.text.strip()
        logging.info(f"My public IP is {ip}")
        return ip
    except Exception as e:
        logging.error(f"Could not determine public IP: {e}")
        return None

def is_active_and_static(ip, port, timeout=5):
    """
    Check if the given IP (and optional port) is active (responsive) and static.
    Follows redirects and verifies that the final URL's hostname and port match.
    """
    url = f"http://{ip}" + (f":{port}" if port else "")
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        if response.status_code != 200:
            return False
        parsed_url = urlparse(response.url)
        final_hostname = parsed_url.hostname
        final_port = parsed_url.port if parsed_url.port else 80
        expected_port = port if port else 80
        if final_hostname and is_valid_ip(final_hostname) and final_hostname == ip and final_port == expected_port:
            return True
        return False
    except Exception as e:
        logging.error(f"Active/static check failed for {url}: {e}")
        return False

def is_known(ip):
    """Check if IP exists in original lists or has been processed."""
    with processed_lock:
        return ip in all_known_ips or ip in processed_set

def process_seed_worker(seed, seed_queue):
    logging.debug(f"Started processing seed: {seed}")
    with processed_lock:
        if seed.ip in processed_set:
            logging.debug(f"Duplicate detected, skipping: {seed.ip}")
            return
        processed_set.add(seed.ip)
    
    url = seed.get_url()
    logging.info(f"Visiting (depth {seed.depth}): {url}")
    
    try:
        response = requests.get(url, timeout=10)
        parsed_url = urlparse(response.url)
        final_url = response.url
    except Exception as e:
        logging.error(f"Error visiting {url}: {e}")
        return
    if response.status_code != 200:
        logging.error(f"Non-OK status {response.status_code} for {url}")
        return
    content = response.text
    if not content:
        logging.error(f"No content from {url}")
        return
    logging.info(f"Visited: {url}")
    
    if seed.depth < MAX_DEPTH:
        found_ips = extract_ip_and_port(content)
        for ip, port, ip_version in found_ips:
            # Skip if the discovered IP matches your public IP.
            if MY_PUBLIC_IP and ip == MY_PUBLIC_IP:
                logging.info(f"Skipping my own public IP: {ip}")
                continue
            if is_known(ip):
                continue

            # Determine new_source_type:
            # For malicious seeds, if the IP fails the active/static check, mark as "benign (auto verdict)"
            new_source_type = seed.source_type
            if seed.source_type == "malicious":
                if not is_active_and_static(ip, port):
                    logging.info(f"IP {ip} did not pass active/static check; marking as benign (auto verdict).")
                    new_source_type = "benign (auto verdict)"
            # (phishing seeds remain "phishing" and whitelist seeds remain "benign")

            with output_lock:
                report_date = datetime.now(timezone.utc).isoformat()
                new_ip_url = f"http://{ip}" + (f":{port}" if port else "")
                source_url = final_url

                # Choose output file and category based on new_source_type.
                if new_source_type == "malicious":
                    category = CATEGORY_MALICIOUS
                    out_file = out_malicious
                    new_ips_from_malicious.add(ip)
                elif new_source_type == "phishing":
                    category = CATEGORY_PHISHING
                    out_file = out_phishing
                    new_ips_from_phishing.add(ip)
                elif new_source_type == "benign (auto verdict)":
                    category = CATEGORY_BENIGN  # empty for benign
                    out_file = out_benign_auto
                    new_ips_from_benign_auto.add(ip)
                else:  # "benign" (non-auto verdict)
                    category = CATEGORY_BENIGN  # empty for benign
                    out_file = out_benign
                    new_ips_from_benign.add(ip)

                comment = (f"Related with ip address detected by heuristics of "
                           f"https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine "
                           f"(Source IP: {seed.ip}, Source URL: {source_url}, Discovered URL: {new_ip_url}, Verdict: {new_source_type})")
                comment = comment[:1024]  # Truncate if necessary
                csv_line = f"{ip},\"{category}\",{report_date},\"{comment}\"\n"
                if out_file:
                    out_file.write(csv_line)
                    out_file.flush()

            with processed_lock:
                processed_set.add(ip)
            new_seed = Seed(ip, new_source_type, ip_version, port=port, depth=seed.depth + 1, source_url=source_url)
            seed_queue.put(new_seed)
            tasks_count.increment()
            logging.debug(f"Enqueued new seed: {new_seed}")
    
    processed_count.increment()
    logging.debug(f"Finished processing seed: {seed}")

def worker_thread(seed_queue):
    while True:
        try:
            seed = seed_queue.get(timeout=5)
        except Empty:
            logging.debug("Queue empty; worker thread exiting.")
            break
        logging.debug(f"Worker fetched seed: {seed}")
        process_seed_worker(seed, seed_queue)
        seed_queue.task_done()

def main():
    global out_malicious, out_phishing, out_benign, out_benign_auto, MY_PUBLIC_IP
    MY_PUBLIC_IP = get_my_public_ip()
    website_dir = os.path.join(os.getcwd(), "website")
    seeds = load_seeds(website_dir)
    if not seeds:
        logging.error("No seed IP addresses found in the seed files.")
        sys.exit(1)
    
    # Open four CSV files with the required headings.
    out_malicious = open("NewDiscoveredIPs_malicious.csv", "w")
    out_phishing = open("NewDiscoveredIPs_phishing.csv", "w")
    out_benign = open("NewDiscoveredIPs_benign.csv", "w")
    out_benign_auto = open("NewDiscoveredIPs_benign_auto_verdict.csv", "w")
    
    header = "IP,Categories,ReportDate,Comment\n"
    out_malicious.write(header)
    out_phishing.write(header)
    out_benign.write(header)
    out_benign_auto.write(header)
    
    seed_queue = Queue()
    for seed in seeds:
        seed_queue.put(seed)
        tasks_count.increment()
    logging.debug(f"Enqueued initial seeds: {len(seeds)}")
    
    pbar = tqdm(total=len(seeds), dynamic_ncols=True, desc="Discovering New IPs")
    processed_count.set_progress_bar(pbar)
    
    with ThreadPoolExecutor(max_workers=1000) as executor:
        for _ in range(1000):
            executor.submit(worker_thread, seed_queue)
    
    seed_queue.join()
    pbar.close()
    
    logging.info(f"Total new IPs found from malicious sources: {len(new_ips_from_malicious)}")
    logging.info(f"Total new IPs found from phishing sources: {len(new_ips_from_phishing)}")
    logging.info(f"Total new IPs found from benign sources: {len(new_ips_from_benign)}")
    logging.info(f"Total new IPs found from benign auto verdict: {len(new_ips_from_benign_auto)}")
    
    out_malicious.close()
    out_phishing.close()
    out_benign.close()
    out_benign_auto.close()
    logging.info("Scan completed.")

if __name__ == "__main__":
    main()

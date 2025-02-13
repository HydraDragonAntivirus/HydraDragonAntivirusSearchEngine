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

# Determine the script directory and create a log folder and log file path
script_dir = os.getcwd()
log_folder = os.path.join(script_dir, "log")
if not os.path.exists(log_folder):
    os.makedirs(log_folder)
log_file = os.path.join(log_folder, "scanner.log")

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file, mode='a')]
)

# Maximum recursion depth
MAX_DEPTH = 10

class Seed:
    def __init__(self, ip, source_type, version, port=None, depth=0, source_url=None):
        self.ip = ip.lower()
        self.source_type = source_type  # "malicious" or "benign"
        self.version = version          # "ipv4" or "ipv6"
        self.port = port                # Port number if available
        self.depth = depth
        self.source_url = source_url    # URL where this IP was found

    def __repr__(self):
        port_str = f":{self.port}" if self.port else ""
        return f"Seed({self.ip}{port_str}, {self.source_type}, {self.version}, depth={self.depth})"

    def get_url(self):
        """Generate the full URL for this seed"""
        if self.port:
            return f"http://{self.ip}:{self.port}"
        return f"http://{self.ip}"

def is_valid_ip(ip_string):
    """
    Validate IP address and return its version or None if invalid.
    Also checks if IP is private.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_string)
        # Skip private, loopback, link-local, multicast, and reserved IPs
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or \
           ip_obj.is_multicast or ip_obj.is_reserved:
            return None

        if isinstance(ip_obj, ipaddress.IPv4Address):
            return "ipv4"
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return "ipv6"
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
    # IPv6 without brackets: e.g. 2001:db8::1 (port information is not considered)
    ipv6_pattern = re.compile(
        r'\b(?P<ip>(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4})\b'
    )

    # Process IPv6 addresses with brackets (including optional port)
    for match in ipv6_bracket_pattern.finditer(text):
        ip = match.group('ip')
        port_str = match.group('port')
        port = int(port_str) if port_str and port_str.isdigit() and 1 <= int(port_str) <= 65535 else None
        ip_version = is_valid_ip(ip)
        if ip_version:
            found_ips.append((ip, port, ip_version))

    # Process IPv4 addresses (with optional port)
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
        ip_version = is_valid_ip(ip)
        if ip_version:
            found_ips.append((ip, port, ip_version))

    # Process IPv6 addresses without brackets (no port information)
    for match in ipv6_pattern.finditer(text):
        ip = match.group('ip')
        # Avoid duplicates if the IP is already added from the bracketed version.
        if any(existing[0] == ip for existing in found_ips):
            continue
        ip_version = is_valid_ip(ip)
        if ip_version:
            found_ips.append((ip, None, ip_version))

    return found_ips

def load_lines(path):
    s = set()
    if os.path.exists(path):
        with open(path, "r") as f:
            for line in f:
                line = line.strip().lower()
                if ':' in line:
                    ip, port = line.rsplit(':', 1)
                else:
                    ip = line
                if ip and is_valid_ip(ip):
                    s.add(ip)
    logging.debug(f"Loaded {len(s)} valid IPs from {path}")
    return s

def load_seeds(website_dir):
    seeds = []
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
    
    global all_known_ips
    all_known_ips = malware_ipv4 | malware_ipv6 | whitelist_ipv4 | whitelist_ipv6
    
    logging.debug(f"Total valid seeds loaded: {len(seeds)}")
    logging.debug(f"Total known IPs: {len(all_known_ips)}")
    return seeds

# Global Collections
all_known_ips = set()   # All IPs from original lists
processed_set = set()   # IPs we've processed
new_ips_from_malicious = set()  # New IPs found from malicious seeds
new_ips_from_benign = set()     # New IPs found from benign seeds

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

# Global file handle and public IP variable
out_new_ips = None
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
    Performs an HTTP GET and then verifies that after redirects the URL's
    hostname still matches the original IP address.
    """
    url = f"http://{ip}" + (f":{port}" if port else "")
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        if response.status_code != 200:
            return False
        final_hostname = urlparse(response.url).hostname
        if final_hostname:
            if is_valid_ip(final_hostname) and final_hostname == ip:
                return True
            else:
                return False
        else:
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
            # Skip if the discovered IP matches your public IP
            if MY_PUBLIC_IP and ip == MY_PUBLIC_IP:
                logging.info(f"Skipping my own public IP: {ip}")
                continue
            if is_known(ip):
                continue

            # For malicious seeds, run heuristic check: if the IP is not active/static,
            # assign an automatic benign verdict.
            new_source_type = seed.source_type
            if seed.source_type == "malicious":
                if not is_active_and_static(ip, port):
                    logging.info(f"IP {ip} did not pass the active/static check; auto-assigning benign verdict.")
                    new_source_type = "benign (auto verdict)"

            with output_lock:
                if new_source_type.startswith("malicious"):
                    new_ips_from_malicious.add(ip)
                else:
                    new_ips_from_benign.add(ip)
                
                new_ip_url = f"http://{ip}" + (f":{port}" if port else "")
                source_url = final_url
                out_new_ips.write(f"{ip},{port if port else ''},{new_source_type},{seed.ip},{source_url},{new_ip_url}\n")
                out_new_ips.flush()

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
    global out_new_ips, MY_PUBLIC_IP
    MY_PUBLIC_IP = get_my_public_ip()

    website_dir = os.path.join(os.getcwd(), "website")
    seeds = load_seeds(website_dir)
    if not seeds:
        logging.error("No seed IP addresses found in the seed files.")
        sys.exit(1)
    
    out_new_ips = open("NewDiscoveredIPs.csv", "w")
    out_new_ips.write("IP,Port,SourceType,SourceIP,SourceURL,DiscoveredURL\n")
    out_new_ips.flush()
    
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
    logging.info(f"Total new IPs found from benign sources: {len(new_ips_from_benign)}")
    
    out_new_ips.close()
    logging.info("Scan completed.")

if __name__ == "__main__":
    main()

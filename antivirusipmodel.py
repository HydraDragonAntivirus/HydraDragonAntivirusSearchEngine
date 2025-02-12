import os
import re
import sys
import time
import logging
import requests
import ipaddress
from queue import Queue
from datetime import datetime
from urllib.parse import urlparse, urljoin
import threading

# Third‑party ML libraries imported at the top.
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# --- Setup Logging ---
LOG_DIR = "log"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "antivirus.log")),
        logging.StreamHandler(sys.stdout),
    ],
)

# --- Global Model Variables and Lock ---
global_model = None
global_vectorizer = None
model_lock = threading.Lock()

# --- Helper Functions ---

def validate_ip(ip_str: str, allow_cidr: bool = True) -> bool:
    """
    Validate if the string is a valid IP address (IPv4 or IPv6) or CIDR notation.
    
    Args:
        ip_str: IP address string to validate.
        allow_cidr: If True, strings containing '/' (CIDR) are allowed;
                    if False, any string with '/' will be rejected.
    
    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        if allow_cidr:
            if '/' in ip_str:
                ipaddress.ip_network(ip_str, strict=False)
            else:
                ipaddress.ip_address(ip_str)
        else:
            if '/' in ip_str:
                return False
            ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def normalize_url(url: str) -> str:
    """If the URL does not start with http:// or https://, prepend http://."""
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return "http://" + url

def load_lines(path: str) -> set:
    """
    Load file contents (one item per line) into a set (all lowercased).
    If the file does not exist, return an empty set.
    """
    result = set()
    if os.path.exists(path):
        with open(path, "r") as f:
            for line in f:
                line = line.strip().lower()
                if line:
                    result.add(line)
    return result

def load_ip_collections(website_dir: str) -> set:
    """
    Load malware IP lists from 'IPv4Malware.txt' and 'IPv6Malware.txt'
    and return the union as a set.
    """
    ipv4_path = os.path.join(website_dir, "IPv4Malware.txt")
    ipv6_path = os.path.join(website_dir, "IPv6Malware.txt")
    ipv4_set = load_lines(ipv4_path)
    ipv6_set = load_lines(ipv6_path)
    return ipv4_set.union(ipv6_set)

def load_whitelist_collections(website_dir: str) -> dict:
    """
    Load whitelist files from the website directory.
    Returns a dictionary with keys:
      - domains, sub_domains, domains_mail, sub_domains_mail, ipv4, ipv6
    """
    files = {
        "domains": "WhiteListDomains.txt",
        "sub_domains": "WhiteListSubDomains.txt",
        "domains_mail": "WhiteListDomainsMail.txt",
        "sub_domains_mail": "WhiteListSubDomainsMail.txt",
        "ipv4": "IPv4WhiteList.txt",
        "ipv6": "IPv6WhiteList.txt",
    }
    collections = {}
    for key, filename in files.items():
        path = os.path.join(website_dir, filename)
        collections[key] = load_lines(path)
    return collections

def is_whitelisted(host: str, whitelist: dict) -> bool:
    """
    Return True if the given host (an IP or domain) is whitelisted.
    For configuration files (which may include CIDR notation) we allow '/'.
    """
    host_lower = host.lower()
    # If host is an IP address or CIDR from configuration, check the IPv4/IPv6 whitelist.
    if validate_ip(host_lower, allow_cidr=True):
        try:
            ip = ipaddress.ip_address(host_lower)
            if ip.version == 4:
                if host_lower in whitelist.get("ipv4", set()):
                    return True
            else:
                if host_lower in whitelist.get("ipv6", set()):
                    return True
        except ValueError:
            pass

    # Otherwise, check the domain whitelist.
    if host_lower in whitelist.get("domains", set()) or host_lower in whitelist.get("domains_mail", set()):
        return True
    for sub in whitelist.get("sub_domains", set()):
        if host_lower == sub or host_lower.endswith("." + sub):
            return True
    for sub in whitelist.get("sub_domains_mail", set()):
        if host_lower == sub or host_lower.endswith("." + sub):
            return True
    return False

def extract_ips_from_text(text: str) -> set:
    """
    Extract potential IP addresses (IPv4 and a simple IPv6 pattern) from text using regex.
    When extracting from free text, we do not allow CIDR notation (i.e. any string containing '/'),
    because we expect only individual IP addresses.
    Returns a set of valid IP strings.
    """
    # Regex for IPv4 addresses
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    # A simple regex for IPv6 addresses (this may not catch all valid forms)
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    ips = set(re.findall(ipv4_pattern, text))
    ips.update(re.findall(ipv6_pattern, text))
    valid_ips = set()
    for ip in ips:
        if validate_ip(ip, allow_cidr=False):
            valid_ips.add(ip)
    return valid_ips

# --- Machine Learning: Training Pipeline ---

def train_model():
    """
    Train a text classifier using the training data saved under the training_data folder.
    It reads data from subdirectories "benign", "malicious", and "unknown" and trains a
    TF-IDF + Multinomial Naive Bayes classifier.
    
    Returns:
        clf: the trained classifier (or None if no training data is available)
        vectorizer: the fitted TF-IDF vectorizer (or None if no training data is available)
    """
    categories = ["benign", "malicious", "unknown"]
    texts = []
    labels = []
    for category in categories:
        dir_path = os.path.join("training_data", category)
        if os.path.exists(dir_path):
            for filename in os.listdir(dir_path):
                file_path = os.path.join(dir_path, filename)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                        texts.append(text)
                        labels.append(category)
                except Exception as e:
                    logging.info(f"Error reading {file_path}: {e}")
    if texts:
        vectorizer = TfidfVectorizer()
        X = vectorizer.fit_transform(texts)
        clf = MultinomialNB()
        clf.fit(X, labels)
        return clf, vectorizer
    else:
        return None, None

def retraining_loop(interval=60):
    """
    Periodically retrain the classifier from the saved training data.
    This function runs in a background thread.
    
    Args:
        interval: time in seconds between retraining attempts.
    """
    global global_model, global_vectorizer
    while True:
        logging.info("Starting retraining process...")
        clf, vec = train_model()
        if clf is not None and vec is not None:
            with model_lock:
                global_model = clf
                global_vectorizer = vec
            logging.info("Retraining completed and model updated.")
        else:
            logging.info("No training data found; skipping retraining.")
        time.sleep(interval)

def predict_risk_from_content(content: bytes) -> str:
    """
    Predict risk from file content. If a trained model is available, use it;
    otherwise, fall back to the dummy heuristic.
    
    Returns one of: "benign", "malicious", or "unknown".
    """
    global global_model, global_vectorizer
    text = content.decode(errors="ignore")
    with model_lock:
        model = global_model
        vectorizer = global_vectorizer
    if model is not None and vectorizer is not None:
        try:
            X = vectorizer.transform([text])
            pred = model.predict(X)[0]
            return pred
        except Exception as e:
            logging.info(f"Error in model prediction: {e}")
    # Fallback dummy heuristic:
    text_lower = text.lower()
    if "benign" in text_lower or "safe" in text_lower:
        return "benign"
    elif "malware" in text_lower or "virus" in text_lower or "trojan" in text_lower:
        return "malicious"
    else:
        return "unknown"

def save_training_data(ip: str, risk: str, content: bytes):
    """
    Save the raw file content as training data.
    Files are stored under training_data/<risk>/, with a filename
    based on the IP (with colons replaced) and a timestamp.
    """
    base_dir = "training_data"
    risk_dir = os.path.join(base_dir, risk)
    os.makedirs(risk_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    safe_ip = ip.replace(":", "_")
    filename = os.path.join(risk_dir, f"{safe_ip}_{timestamp}.dat")
    with open(filename, "wb") as f:
        f.write(content)

def update_progress(processed: int, total: int):
    """Print progress on the same line."""
    print(f"\rProcessed: {processed}/{total}", end="")
    sys.stdout.flush()

def write_classification_files(classification: dict):
    """
    Write final classification results to files.
    For each IP in the classification map, the IP is written to one of:
      - IPv4BenignZeroDay.txt or IPv6BenignZeroDay.txt (for benign)
      - IPv4SuspiciousZeroDay.txt or IPv6SuspiciousZeroDay.txt (for malicious)
      - IPv4UnknownZeroDay.txt or IPv6UnknownZeroDay.txt (for unknown)
    """
    ipv4_benign, ipv4_malicious, ipv4_unknown = [], [], []
    ipv6_benign, ipv6_malicious, ipv6_unknown = [], [], []
    for ip, risk in classification.items():
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if parsed.version == 4:
            if risk == "benign":
                ipv4_benign.append(ip)
            elif risk == "malicious":
                ipv4_malicious.append(ip)
            else:
                ipv4_unknown.append(ip)
        else:
            if risk == "benign":
                ipv6_benign.append(ip)
            elif risk == "malicious":
                ipv6_malicious.append(ip)
            else:
                ipv6_unknown.append(ip)
    with open("IPv4BenignZeroDay.txt", "w") as f:
        f.write("\n".join(ipv4_benign))
    with open("IPv4SuspiciousZeroDay.txt", "w") as f:
        f.write("\n".join(ipv4_malicious))
    with open("IPv4UnknownZeroDay.txt", "w") as f:
        f.write("\n".join(ipv4_unknown))
    with open("IPv6BenignZeroDay.txt", "w") as f:
        f.write("\n".join(ipv6_benign))
    with open("IPv6SuspiciousZeroDay.txt", "w") as f:
        f.write("\n".join(ipv6_malicious))
    with open("IPv6UnknownZeroDay.txt", "w") as f:
        f.write("\n".join(ipv6_unknown))

# --- Task and Processing Functions ---

class Task:
    def __init__(self, url: str, depth: int):
        self.url = url
        self.depth = depth

def process_url(task: Task, whitelist: dict, processed_set: set, classification_map: dict) -> list:
    """
    Download a URL and then:
      - If the content is HTML, extract IP addresses from the text using regex.
      - Classify the content using our (model-based) heuristic and save training data.
      - Update the global classification_map (allowing benign to override previous malicious/unknown classifications).
    Returns a list of new URLs (constructed as "http://<ip>") to process.
    """
    logging.info(f"Processing URL (depth {task.depth}): {task.url}")

    if task.url in processed_set:
        return []
    processed_set.add(task.url)

    normalized_url = normalize_url(task.url)
    parsed = urlparse(normalized_url)
    host = parsed.hostname
    if not host:
        logging.info(f"Failed to parse URL: {normalized_url}")
        return []
    host = host.lower()

    # Use validate_ip() to check if the host is a valid IP.
    # Allow CIDR here because configuration files may include CIDR notations.
    if not validate_ip(host, allow_cidr=True):
        logging.info(f"Skipping non-IP host: {host}")
        return []

    # Skip whitelisted hosts.
    if is_whitelisted(host, whitelist):
        logging.info(f"Skipping whitelisted host: {host}")
        return []

    try:
        resp = requests.get(normalized_url, timeout=10)
    except Exception as e:
        logging.info(f"Error downloading {normalized_url}: {e}")
        return []
    if resp.status_code != 200:
        logging.info(f"Failed to download {normalized_url} (status: {resp.status_code})")
        return []
    content_type = resp.headers.get("content-type", "").lower()
    content = resp.content
    if not content:
        logging.info(f"No content downloaded from {normalized_url}")
        return []

    new_urls = []
    # If the content is HTML, extract IP addresses from its text using regex.
    if "text/html" in content_type:
        text = content.decode(errors="ignore")
        extracted_ips = extract_ips_from_text(text)
        for ip in extracted_ips:
            if not is_whitelisted(ip, whitelist):
                # Construct a URL from the IP (assume HTTP).
                new_urls.append("http://" + ip)
        logging.info(f"Extracted {len(new_urls)} new IP URL(s) from HTML: {normalized_url}")

    # Classify the content using our model-based heuristic.
    risk = predict_risk_from_content(content)
    logging.info(f"URL: {normalized_url} classified as {risk}")

    # Update the classification map (allowing benign to override previous classifications).
    if host in classification_map:
        prev = classification_map[host]
        if prev != "benign" and risk == "benign":
            classification_map[host] = risk
            logging.info(f"Reclassified {host} as benign")
        elif prev == "unknown" and risk == "malicious":
            classification_map[host] = risk
            logging.info(f"Updated {host} classification from unknown to malicious")
    else:
        classification_map[host] = risk

    # Save training data.
    try:
        save_training_data(host, risk, content)
    except Exception as e:
        logging.info(f"Failed to save training data for {host}: {e}")

    return new_urls

# --- Main Function ---

def main():
    # Setup directories.
    current_dir = os.getcwd()
    website_dir = os.path.join(current_dir, "website")
    os.makedirs(website_dir, exist_ok=True)
    os.makedirs("training_data", exist_ok=True)

    # Start the background retraining thread (runs every 60 seconds).
    retraining_thread = threading.Thread(target=retraining_loop, args=(60,), daemon=True)
    retraining_thread.start()

    # Load seed IPs from malware lists.
    union_ips = load_ip_collections(website_dir)
    if not union_ips:
        logging.info("No IP addresses found in your malware lists.")
        return
    logging.info(f"Starting scan for {len(union_ips)} IP addresses.")

    # Load whitelist.
    whitelist = load_whitelist_collections(website_dir)

    # Shared data structures.
    processed_set = set()
    classification_map = {}
    task_queue = Queue()

    # Enqueue each seed IP (each IP is treated as a URL).
    for ip in union_ips:
        task_queue.put(Task(ip, 0))

    max_depth = 10
    total_count = task_queue.qsize()
    processed_count = 0

    # Process tasks synchronously.
    while not task_queue.empty():
        task = task_queue.get()
        new_urls = process_url(task, whitelist, processed_set, classification_map)
        processed_count += 1
        update_progress(processed_count, total_count)
        # If the current depth is less than max_depth, enqueue discovered URLs.
        if task.depth < max_depth:
            for url in new_urls:
                total_count += 1
                task_queue.put(Task(url, task.depth + 1))
        task_queue.task_done()

    print()  # Newline after progress.
    logging.info(f"\nScan completed. Total URLs processed: {processed_count}")
    write_classification_files(classification_map)
    logging.info("Classification files written.")

if __name__ == "__main__":
    main()

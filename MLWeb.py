#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import requests
import logging
import nltk
from nltk.tokenize import word_tokenize
from tqdm.contrib.concurrent import thread_map
from nltk import FreqDist

# Download necessary NLTK resources
nltk.download('punkt')
nltk.download('punkt_tab')
nltk.download('words')

# Load NLTK word corpus and define filter function
from nltk.corpus import words
def filter_meaningful_words(word_list):
    # Only allow alphabetic, lowercase words
    return [word for word in word_list if word.isalpha() and word.islower()]

nltk_words = set(words.words())

# Configure logging to output messages to MLWeb.log file
logging.basicConfig(
    level=logging.INFO,
    filename='MLWeb.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define the website rules directory using the current working directory
website_rules_dir = os.path.join(os.getcwd(), "website")

# Define file paths for each category (each file contains IP addresses)
ipv4_malware_path         = os.path.join(website_rules_dir, "IPv4Malware.txt")
ipv4_spam_path            = os.path.join(website_rules_dir, "IPv4Spam.txt")
ipv4_bruteforce_path      = os.path.join(website_rules_dir, "IPv4BruteForce.txt")
ipv4_phishing_active_path = os.path.join(website_rules_dir, "IPv4PhishingActive.txt")
ipv4_phishing_inactive_path = os.path.join(website_rules_dir, "IPv4PhishingInactive.txt")
ipv4_whitelist_path       = os.path.join(website_rules_dir, "IPv4Whitelist.txt")
ipv6_spam_path            = os.path.join(website_rules_dir, "IPv6Spam.txt")
ipv6_malware_path         = os.path.join(website_rules_dir, "IPv6Malware.txt")
ipv4_ddos_path            = os.path.join(website_rules_dir, "IPv4DDoS.txt")
ipv6_ddos_path            = os.path.join(website_rules_dir, "IPv6DDoS.txt")
ipv6_whitelist_path       = os.path.join(website_rules_dir, "IPv6Whitelist.txt")

# Map each category to its corresponding file path and a label.
# Here "legitimate" indicates benign websites; others are "malicious".
files = {
    "IPv4Malware":         (ipv4_malware_path, "malicious"),
    "IPv4Spam":            (ipv4_spam_path, "malicious"),
    "IPv4BruteForce":      (ipv4_bruteforce_path, "malicious"),
    "IPv4PhishingActive":  (ipv4_phishing_active_path, "malicious"),
    "IPv4PhishingInactive":(ipv4_phishing_inactive_path, "malicious"),
    "IPv4Whitelist":       (ipv4_whitelist_path, "legitimate"),
    "IPv6Spam":            (ipv6_spam_path, "malicious"),
    "IPv6Malware":         (ipv6_malware_path, "malicious"),
    "IPv4DDoS":            (ipv4_ddos_path, "malicious"),
    "IPv6DDoS":            (ipv6_ddos_path, "malicious"),
    "IPv6Whitelist":       (ipv6_whitelist_path, "legitimate")
}

# Function to load IP addresses from a file (each line contains one IP address)
def load_ips_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
            logging.info(f"Loaded {len(ips)} IPs from {file_path}")
            return ips
    except Exception as e:
        logging.error(f"Error reading {file_path}: {e}")
        return []

# Function to fetch website content using an IP address
def fetch_website_content(ip):
    url = f"http://{ip}"  # Change to "https://" if necessary
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            logging.error(f"Request failed for {url}: Status code {response.status_code}")
            return ""
    except Exception as e:
        logging.error(f"Error fetching {url}: {e}")
        return ""

# Function to fetch website content and tokenize it using NLTK.
def fetch_and_tokenize(ip):
    content = fetch_website_content(ip)
    if content:
        tokens = word_tokenize(content)
        # Use your filter to keep only meaningful words and words found in the English corpus.
        tokens = filter_meaningful_words(tokens)
        tokens = [token for token in tokens if token in nltk_words]
        return tokens
    return []

# Build dataset: for each category, use thread_map to fetch and tokenize website content concurrently.
category_tokens = {"malicious": [], "legitimate": []}

for category, (file_path, label) in files.items():
    ips = load_ips_from_file(file_path)
    if not ips:
        continue

    # Use thread_map for concurrent processing with an integrated tqdm progress bar.
    tokens_lists = thread_map(fetch_and_tokenize, ips, 
                              desc=f"Processing IPs in {category}", 
                              unit="IP")
    
    # Flatten the list of token lists into one list for this category.
    for tokens in tokens_lists:
        category_tokens[label].extend(tokens)

logging.info("Completed processing all websites.")

# Create a signature for each category using frequency distribution.
def create_signature(tokens, top_n=20):
    freq_dist = FreqDist(tokens)
    common_words = [word for word, _ in freq_dist.most_common(top_n)]
    return common_words

malicious_signature = create_signature(category_tokens["malicious"], top_n=20)
benign_signature    = create_signature(category_tokens["legitimate"], top_n=20)

# Optionally filter out words that are common to both signatures.
unique_malicious = [word for word in malicious_signature if word not in benign_signature]
unique_benign    = [word for word in benign_signature if word not in malicious_signature]

print("Malicious Signature (unique words):")
print(unique_malicious)
print("\nBenign Signature (unique words):")
print(unique_benign)

logging.info(f"Malicious Signature: {unique_malicious}")
logging.info(f"Benign Signature: {unique_benign}")

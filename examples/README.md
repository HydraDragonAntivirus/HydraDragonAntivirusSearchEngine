# Hydra Dragon Antivirus Search Engine - JSON Settings Overview

Below is a detailed explanation of the JSON configuration settings used by the tool:

---

## Scanning & Concurrency Settings

- **MaxThreads**: `100`  
  *Specifies the maximum number of concurrent threads to use during the scan.*

---

## CSV Reporting Settings

- **CsvMaxLines**: `10000`  
  *Determines the maximum number of lines allowed per CSV file before it is rotated. Even if set higher, the tool enforces a cap of 10,000 lines per file (to comply with AbuseIPDB limits).*

- **CsvMaxSize**: `2097152`  
  *Specifies the maximum allowed CSV file size in bytes (approximately 2 MB). When this limit is exceeded, a new file is created.*

- **OutputFile**: `"output\\BulkReport.csv"`  
  *Defines the file path for the bulk report CSV, which contains IPs that are not classified as benign.*

- **WhiteListOutputFile**: `"output\\WhitelistReport.csv"`  
  *Defines the file path for the whitelist report CSV, which logs benign IP addresses.*

---

## Category Identifiers & Comment Template

- **CategoryMalicious**: `"20"`  
  *Identifier used for IP addresses flagged as malicious.*

- **CategoryPhishing**: `"7"`  
  *Identifier used for phishing-related IP addresses.*

- **CategoryDDoS**: `"18"`  
  *Identifier used for IP addresses involved in DDoS attacks.*

- **CommentTemplate**:  
 *"Related with ip address detected by heuristics of https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine (Source IP: {ip}, Source URL: {source_url}, Discovered URL: {discovered_url}, Verdict: {verdict})"*

 *Template for generating detailed comments for each reported IP, with placeholders for dynamic values: `{ip}`, `{source_url}`, `{discovered_url}` and `{verdict}`.*

---

## Seed Files for IP Lists

These settings specify the file paths (or comma-separated lists) that contain the initial seed IP addresses for each category:

- **MalwareFilesIPv6**: `"website\\IPv6Malware.txt"`  
*File containing IPv6 addresses associated with malware.*

- **MalwareFilesIPv4**: `"website\\IPv4Malware.txt"`  
*File containing IPv4 addresses associated with malware.*

- **DDoSFilesIPv6**: `""`  
*No file specified for IPv6 DDoS-related addresses.*

- **DDoSFilesIPv4**: `"website\\IPv4DDoS.txt"`  
*File containing IPv4 addresses related to DDoS attacks.*

- **PhishingFilesIPv6**: `""`  
*No file specified for IPv6 phishing-related addresses.*

- **PhishingFilesIPv4**: `"website\\IPv4PhishingActive.txt, website\\IPv4PhishingInActive.txt"`  
*Comma-separated list of files for IPv4 phishing addresses (active and inactive).*

- **WhiteListFilesIPv6**: `"website\\IPv6WhiteList.txt"`  
*File listing IPv6 addresses considered safe.*

- **WhiteListFilesIPv4**: `"website\\IPv4WhiteList.txt"`  
*File listing IPv4 addresses considered safe.*

---

## Primary Paths for IP Categories

These settings define canonical file paths for each category and IP version:

- **WhiteListPathIPv4**: `"website\\IPv4WhiteList.txt"`  
- **WhiteListPathIPv6**: `"website\\IPv6WhiteList.txt"`  
- **PhishingPathIPv4**: `"website\\IPv4Phishing.txt"`  
- **PhishingPathIPv6**: `"website\\IPv6Phishing.txt"`  
- **DDoSPathIPv4**: `"website\\IPv4DDoS.txt"`  
- **DDoSPathIPv6**: `"website\\IPv6DDoS.txt"`  
- **MalwarePathIPv4**: `"website\\IPv4Malware.txt"`  
- **MalwarePathIPv6**: `"website\\IPv6Malware.txt"`  

*These paths ensure that the tool knows where to load or store IP lists for each specific category.*

---

## Duplicate Handling Settings

To manage duplicate entries, the following settings determine whether duplicates are allowed and where to log them:

- **AllowDuplicateWhitelistIPv4**: `"false"`  
- **AllowDuplicateWhitelistIPv6**: `"false"`  
- **AllowDuplicatePhishingIPv4**: `"false"`  
- **AllowDuplicatePhishingIPv6**: `"false"`  
- **AllowDuplicateDDoSIPv4**: `"false"`  
- **AllowDuplicateDDoSIPv6**: `"false"`  
- **AllowDuplicateMaliciousIPv4**: `"false"`  
- **AllowDuplicateMaliciousIPv6**: `"false"`  

*With these flags set to `"false"`, duplicate IP addresses are skipped during the scan.*

- **DuplicateWhitelistFileIPv4**: `"website\\whitelist_ipv4_duplicates.csv"`  
- **DuplicateWhitelistFileIPv6**: `"website\\whitelist_ipv6_duplicates.csv"`  
- **DuplicatePhishingFileIPv4**: `"website\\phishing_ipv4_duplicates.csv"`  
- **DuplicatePhishingFileIPv6**: `"website\\phishing_ipv6_duplicates.csv"`  
- **DuplicateDDoSFileIPv4**: `"website\\ddos_ipv4_duplicates.csv"`  
- **DuplicateDDoSFileIPv6**: `"website\\ddos_ipv6_duplicates.csv"`  
- **DuplicateMaliciousFileIPv4**: `"website\\malicious_ipv4_duplicates.csv"`  
- **DuplicateMaliciousFileIPv6**: `"website\\malicious_ipv6_duplicates.csv"`  

*These file paths are used to log any duplicate entries (if encountered or allowed).*

---

**Note:** Adjust these settings as needed for your environment. The above configuration is designed to balance thorough scanning with efficient reporting and duplicate management.

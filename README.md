# Hydra Dragon Antivirus Search Engine
- Website: https://hydradragonantivirus.github.io/HydraDragonAntivirusSearchEngine/

## WARNING
This program displays your public IP address. Be aware that when running this tool, your public IP will be queried and shown in the logs. Use this program only in secure environments.

## Overview

**Hydra Dragon Antivirus Search Engine** is a specialized tool designed to find **zero-day malicious IP addresses** on the web. It's not a full antivirus product, but instead, it uses databases to extract **related unknown IP addresses**. It doesn’t scan IP address content with traditional antivirus engines; rather, it searches for patterns and connections to help identify malicious activity.

This project was built to assist the **Comodo Antivirus community**, where Comodo blocks known malware and malicious IPs through its firewall and website filtering. However, it sometimes misses unknown C2 (Command & Control) servers, leading to the exposure of sensitive data on the dark web. The goal of this tool is to fill that gap and **protect users from data theft by identifying unknown malicious IPs**.

If you detect malware with your original IP, it's highly recommended to remove it from the logs and create an **AbuseIPDB account** to avoid being reported. The tool can be used to check for these unknown IP addresses, and new IPs should be submitted to **AbuseIPDB**.

### **Important Notice**
- **Logs Tab**: You will need to check the **Logs tab** in the application to view the latest scan results.
- **AbuseIPDB Integration**: This tool is specifically designed to help improve the **AbuseIPDB** database by detecting malicious IPs that are not yet flagged.
- **Example JSON Configuration**: You can use the example folder to load settings for the scan.
- **GoodByeDPI**: To avoid country bans, use [GoodByeDPI](https://github.com/ValdikSS/GoodbyeDPI).
- **Use Windows**: Due to the WinError 10061 check, we recommend using the Windows operating system.

### **What this Tool Does**:
- **Malicious IP Finder**: It helps identify potentially malicious or unknown IPs (both IPv4 and IPv6).
- **AbuseIPDB Integration**: Specifically targets AbuseIPDB's database to identify and report malicious IP addresses, filling in gaps where unknown C2 servers might be missed.
- **Zero-Day Detection**: Searches for zero-day malicious IPs that may have slipped under the radar of traditional antivirus software.

### **What this Tool Does Not Do**:
- It does **not scan** IP address content with traditional antivirus engines.
- It does not provide full antivirus protection, but rather focuses on identifying related unknown IP addresses.

---

## Features

- **Real-Time Monitoring**: Continuously scans for malicious activities in real time.
- **Benign Auto Verdicts**: Automatically classifies IPs and URLs based on their activity and behavior (Benign Auto Verdict 1, 2, 3).
- **Efficient Reporting**: Generates two CSV reports:
  - **BulkReport.csv** (and split files if necessary) for non-benign IPs.
  - **WhitelistReport.csv** (and split files if necessary) for benign IPs.
- **IPv4 and IPv6 Support**: Supports both IPv4 and IPv6 address spaces.
- **Database Integration**: Helps integrate with **AbuseIPDB** to flag potentially malicious IP addresses.
- **Logs Tab**: Monitors the logs for real-time updates and detected IPs.
- **CSV File Management**: Automatically stops the scan when the CSV file reaches 10,000 lines (if that limit is set) or splits the file into multiple parts if a higher limit is provided.

---

## **Benign Auto Verdicts in Malware Detection**

Hydra Dragon Antivirus Search Engine uses **Benign Auto Verdicts** to classify IPs based on their activity and status. These verdicts help determine whether an IP that was previously flagged as malicious has become benign or remains a threat.

### **1. Benign Auto Verdict 1: Malicious to Benign**
- **Scenario**: An IP flagged as malicious is now **inactive** or **non-static**.
- **Action**: It is marked as **benign (auto verdict 1)** and added to the whitelist.

### **2. Benign Auto Verdict 2: Active and Static Benign**
- **Scenario**: An IP identified as benign remains **active** and **static**.
- **Action**: It is marked as **benign (auto verdict 2)** and added to the whitelist.

### **3. Benign Auto Verdict 3: Dead IP**
- **Scenario**: A benign IP becomes **inactive** or **non-static** (dead IP).
- **Action**: It is marked as **benign (auto verdict 3)** and added to the whitelist.

### **30-Day Monitoring Requirement**
- **Why 30 Days of Monitoring**: An IP that has been marked as benign may **reactivate** or **become malicious** after a period of inactivity. To ensure thorough verification, a 30-day monitoring period is required.
- **Monitoring Process**: The system keeps track of inactive or static IPs for 30 days to ensure that they remain benign. If the IP becomes active again, the system rechecks its status and reclassifies it if necessary. However, due to the urgency of detecting threats, the system will **quickly classify IPs as benign** based on the current checks and continue to monitor them.

---

## Setup and Usage

### Prerequisites
- Python 3.8 or later.
- Hydra Dragon Antivirus Search Engine requires internet access to query public databases for known malicious IPs.

### Installation

1. Clone the repository to your local machine:

git clone https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine.git

2. Navigate to the project directory:

cd HydraDragonAntivirusSearchEngine

3. Install the dependencies:

pip install -r requirements.txt

4. Run the application:

python scanner.py

5. (Optional) Build the executable (Windows only):

python setup.py build

### Configuring the Application
- The application is configured via a settings dialog with individual input fields.
- You can load, edit, and save the JSON settings through the GUI.
- Adjust parameters such as **MaxDepth**, **MaxThreads**, **CsvMaxLines**, and **CsvMaxSize**.
- Specify the file lists for **malware**, **DDoS**, **phishing**, and **whitelist** IPs.
- The CSV output files for bulk reporting and whitelist are generated based on these settings. If the CSV file exceeds the configured line count, the application will stop the scan (if the limit is 10,000) or automatically split the file (if a higher limit is set).

### Running the Scan
1. Load your JSON settings file using the GUI.
2. Optionally edit the settings via the provided input fields.
3. Click the **Start Scan** button to begin scanning.
4. Monitor the progress and view log messages in the GUI. All log messages are also written to `log.txt`.

### Real-Time Monitoring and Reporting
- **Real-time CSV generation**: The application generates two CSV files:
- **BulkReport.csv** (and additional files with suffixes if split) for non-benign IPs.
- **WhitelistReport.csv** (and additional files with suffixes if split) for benign IPs.
- **Log Monitoring**: All log messages are displayed in the GUI and written to `log.txt`.

## Deep Recursive Scanning for Malicious IP Detection

Hydra Dragon Antivirus Search Engine performs **extensive deep scanning** to detect unknown **zero-day malicious IPs**. Unlike traditional antivirus tools that rely on static IP lists, this tool recursively explores related websites by following links and analyzing content.

- **Advanced Deep Scanning**: Uses a **depth-first search** strategy to uncover IP addresses linked to known sources.
- **Increased Coverage**: Helps detect **C2 (Command & Control) servers** and other malicious entities that may not be immediately visible.
- **Recursive Discovery**: Continuously extracts new URLs and IP addresses, building a comprehensive map of potentially malicious IPs.
- **Depth Control**: The maximum scan depth is configurable, ensuring thorough investigation without endless recursion.

The tool ensures that even the most **obscure and hidden malicious IPs** are identified, providing a deep dive into the web's dark corners where malicious activities may go undetected.

---

## Credits

- **HydraDragonAntivirus** (main developer, repo owner, Python developer, designer)

## TODO
- Implement scanning from different locations to collect more data.
- Interagate Snort 2.9.
- Interagate DeepSeek-Coder-1.3b.
- Interagate ClamAV.
- Interagate Cloud Antivirus.
- Interagate HydraDragonAntivirus.
- Setup with Inno Setup.

## License

This project is licensed under the **GPLv2 License** - see the [LICENSE](LICENSE) file for details.

---

### Download Link
You can download the latest release of the **Hydra Dragon Antivirus Search Engine** from the link below:

[Download Hydra Dragon Antivirus Search Engine (Latest Release)](https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine/releases/latest)

---

### GitHub Repository
For more information and updates, visit the official repository on GitHub:

[Hydra Dragon Antivirus Search Engine - GitHub Repository](https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine)

---
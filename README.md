# Hydra Dragon Antivirus Search Engine

## Overview

**Hydra Dragon Antivirus Search Engine** is a specialized tool designed to find **zero-day malicious IP addresses** on the web. It's not a full antivirus product, but instead, it uses databases to extract **related unknown IP addresses**. It doesn’t scan IP address content with traditional antivirus engines, rather it searches for patterns and connections to help identify malicious activity. 

This project was built to assist the **Comodo Antivirus community**, where Comodo blocks known malware containment and malicious IPs through its firewall and website filtering. However, it sometimes misses unknown C2 (Command & Control) servers, leading to the exposure of sensitive data on the dark web. The goal of this tool is to fill that gap and **protect users from data theft by identifying unknown malicious IPs**.

If you detect malware with your original IP, it's highly recommended to remove it from the logs and create an **AbuseIPDB account** to avoid being reported. The tool can be used to check for these unknown IP addresses, and new IPs should be submitted to **AbuseIPDB**.

### **Important Notice**
- **Logs Tab**: You will need to check the **Logs tab** in the application to view the latest results of the scan.
- **AbuseIPDB Integration**: This tool is specifically designed to help improve the **AbuseIPDB** database by detecting malicious IPs that are not yet flagged.
- **Example JSON Configuration**: You can use the example folder to load settings for the scan.
  
### **What this Tool Does**:
- **Malicious IP Finder**: It helps identify potentially malicious or unknown IPs (both IPv4 and IPv6).
- **AbuseIPDB Integration**: Specifically targets AbuseIPDB's database to identify and report malicious IP addresses, filling in gaps where unknown C2 servers might be missed.
- **Zero-Day Detection**: Searches for zero-day malicious IPs that may have slipped under the radar of traditional antivirus software.
  
### **What this Tool Does Not Do**:
- It does **not scan** IP address content via HydraDragonAntivirus engines.
- It does not provide full antivirus protection, but rather focuses on identifying related unknown IP addresses.
  
---

## Features

- **Real-Time Monitoring**: Continuously scans for malicious activities in real-time.
- **Benign Auto Verdicts**: Automatically classifies IPs and URLs based on their activity and behavior (Benign Auto Verdict 1, 2, 3).
- **Efficient Reporting**: Generates bulk and whitelist reports in CSV format for easy export and analysis.
- **IPv4 and IPv6 Support**: Supports both IPv4 and IPv6 address spaces.
- **Database Integration**: Helps integrate with **AbuseIPDB** to flag potentially malicious IP addresses.
- **Logs Tab**: Monitors the logs for real-time updates and detected IPs.

---

## **Benign Auto Verdicts in Malware Detection**

Hydra Dragon Antivirus Search Engine uses **Benign Auto Verdicts** to classify IPs based on their activity and status. The verdicts help to classify whether an IP that was previously flagged as malicious has become benign or is still a threat.

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
- **.NET 8.0** or later for compiling and running the project.
- **Hydra Dragon Antivirus Search Engine** requires internet access to query public databases for known malicious IPs.

### Installation

1. Clone the repository to your local machine:

   `git clone https://github.com/HydraDragonAntivirus/HydraDragonAntivirusSearchEngine.git`

2. Navigate to the project directory and restore the dependencies:

   `cd HydraDragonAntivirusSearchEngine`
   `cd Hydra Dragon Antivirus Search Engine`

   `dotnet restore`

3. Build and run the application:

   `dotnet run`

### Configuring the Application
- The system is configured through the **MainWindow.xaml.cs** file. Adjust settings such as **MaxDepth**, **MaxThreads**, **CsvMaxLines**, and **CsvMaxSize** according to your needs.
- CSV output files for both **bulk reports** and **whitelist** can be configured in the settings dialog within the app.

### Running the Scan
1. Choose the files to scan by selecting the relevant **malware**, **DDoS**, **phishing**, and **whitelist** files.
2. Click the **Start Scan** button to begin scanning.
3. Monitor the progress and view logs through the **Logs Tab**.

### Real-Time Monitoring
- **Real-time CSV generation**: Enable real-time logging of both **bulk** and **whitelist** entries to separate CSV files.
- **Log Search**: Use the search functionality in the **Logs Tab** to filter through log entries.

## Deep Recursive Scanning for Malicious IP Detection

Hydra Dragon Antivirus Search Engine is built to perform **extensive deep scanning** in order to detect unknown **zero-day malicious IPs**. Unlike traditional antivirus tools, it doesn't simply scan static IP lists but dives deeper into the web by following links and analyzing **related websites**. The tool performs **recursive searches** with the ability to go multiple levels deep, systematically exploring websites linked to known sources to uncover hidden malicious IP addresses.

- **Very Super Advanced Deep Depth Scanning**: The system utilizes a **depth-first search** strategy, exploring links on discovered websites to uncover more IPs at each level. For example, if a malicious IP is discovered on a website, the tool will follow links on that website to uncover even more IPs, continuing this process to an arbitrary level (the **max depth** can be configured).
- **Increased Coverage**: This approach helps to detect **C2 (Command and Control) servers** and other malicious entities that might not be immediately visible but are **linked through multiple levels** of related websites.
- **Recursive Discovery**: At each level of depth, the tool extracts new URLs, processes them, and uncovers new IP addresses, creating a **comprehensive relationship map** of potentially harmful IPs that may evade traditional detection methods.
- **Depth Control**: You can configure how deep the scan goes, ensuring that the system can explore as many levels as required, offering a **thorough investigation of the internet's IP landscape**.

The system ensures that even the most **obscure and hidden malicious IPs** are identified by traversing complex webs of related websites, providing **a deep dive into the internet's dark corners** where malicious activity might be taking place undetected.

---

## Credits

- **HydraDragonAntivirus** (main developer, repo owner, Python developer, designer)

## TODO
- Add the ability to **pause the scan** for more control during long-running processes.
- Scan from different locations to collect more data

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

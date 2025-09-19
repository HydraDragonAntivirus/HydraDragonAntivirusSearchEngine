#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import csv
import json
import logging
from functools import lru_cache

# --- Basic Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "website", "reports")
LOG_DIR = os.path.join(BASE_DIR, "logs")
SETTINGS_FILE = os.path.join(BASE_DIR, "settings", "settings.json")

os.makedirs(LOG_DIR, exist_ok=True)

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "post_script.log")),
        logging.StreamHandler()
    ]
)

# --- Settings Loading ---
@lru_cache(maxsize=1)
def load_settings():
    """Loads settings from settings.json"""
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            logging.info(f"Loading settings from {SETTINGS_FILE}")
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"FATAL: {SETTINGS_FILE} not found. Exiting.")
        return None
    except json.JSONDecodeError:
        logging.error(f"FATAL: Invalid JSON in {SETTINGS_FILE}. Exiting.")
        return None

def filter_bulk_report():
    """
    Creates FilteredBulkReport.csv by removing any whitelisted IPs from BulkReport.csv.
    """
    bulk_path = os.path.join(REPORTS_DIR, "BulkReport.csv")
    whitelist_path = os.path.join(REPORTS_DIR, "WhitelistReport.csv")
    filtered_bulk_path = os.path.join(REPORTS_DIR, "FilteredBulkReport.csv")

    if not os.path.exists(bulk_path):
        logging.warning(f"Bulk report not found at {bulk_path}. Skipping filtering.")
        return

    whitelisted_ips = set()
    if os.path.exists(whitelist_path):
        try:
            with open(whitelist_path, 'r', encoding='utf-8') as wf:
                reader = csv.reader(wf)
                next(reader, None)  # skip header
                for row in reader:
                    if row:
                        whitelisted_ips.add(row[0].strip())
            logging.info(f"Loaded {len(whitelisted_ips)} IPs from the whitelist.")
        except Exception as e:
            logging.error(f"Could not read whitelist report: {e}")
    else:
        logging.warning(f"Whitelist report not found at {whitelist_path}. Cannot filter.")

    try:
        filtered_records = []
        header = []
        with open(bulk_path, 'r', encoding='utf-8') as bf:
            reader = csv.reader(bf)
            header = next(reader, None)
            for row in reader:
                if row and row[0].strip() not in whitelisted_ips:
                    filtered_records.append(row)
        
        logging.info(f"Found {len(filtered_records)} non-whitelisted IPs for the filtered report.")

        with open(filtered_bulk_path, "w", newline='', encoding='utf-8') as ff:
            writer = csv.writer(ff)
            if header:
                writer.writerow(header)
            writer.writerows(filtered_records)

        logging.info(f"Filtered Bulk Report created successfully at: {filtered_bulk_path}")
    except Exception as e:
        logging.error(f"An error occurred during filtering: {e}")


def generate_abuseipdb_report(settings):
    """
    Generates an AbuseIPDB-compatible report from the filtered bulk report.
    """
    filtered_bulk_path = os.path.join(REPORTS_DIR, "FilteredBulkReport.csv")
    abuseipdb_report_path = os.path.join(REPORTS_DIR, "AbuseIPDB_Report.csv")
    
    category_map = settings.get("AbuseIPDBCategories")
    if not category_map:
        logging.error("AbuseIPDBCategories not found in settings.json. Cannot generate report.")
        return

    if not os.path.exists(filtered_bulk_path):
        logging.warning(f"Filtered bulk report not found at {filtered_bulk_path}. Cannot generate AbuseIPDB report.")
        return

    try:
        abuseipdb_records = []
        with open(filtered_bulk_path, 'r', encoding='utf-8') as f:
            # Using DictReader for easier column access by name
            reader = csv.DictReader(f)
            for row in reader:
                text_categories = row.get("Categories", "").split(',')
                numeric_categories = {category_map.get(cat.strip()) for cat in text_categories if cat.strip() in category_map}
                
                # Remove None if a category wasn't found and join with comma
                numeric_categories_str = ",".join(sorted(list(filter(None, numeric_categories))))

                if numeric_categories_str:
                    abuseipdb_records.append([
                        row["IP"],
                        numeric_categories_str,
                        row["ReportDate"],
                        row["Comment"]
                    ])
        
        logging.info(f"Processed {len(abuseipdb_records)} records for AbuseIPDB report.")

        with open(abuseipdb_report_path, "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write a header consistent with the other reports for UI compatibility
            writer.writerow(["IP", "Categories", "ReportDate", "Comment"])
            writer.writerows(abuseipdb_records)
        
        logging.info(f"AbuseIPDB Report created successfully at: {abuseipdb_report_path}")

    except Exception as e:
        logging.error(f"An error occurred while generating the AbuseIPDB report: {e}")


if __name__ == "__main__":
    logging.info("--- Starting Post-Scan Script ---")
    settings = load_settings()
    if settings:
        filter_bulk_report()
        generate_abuseipdb_report(settings)
    else:
        logging.error("Could not load settings. Aborting post-scan processing.")
    logging.info("--- Post-Scan Script Finished ---")

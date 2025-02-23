#!/usr/bin/env python3
import os
import csv

def filter_bulk_report(output_folder):
    bulk_path = os.path.join(output_folder, "BulkReport.csv")
    whitelist_path = os.path.join(output_folder, "WhitelistReport.csv")
    filtered_bulk_path = os.path.join(output_folder, "FilteredBulkReport.csv")

    if not os.path.exists(bulk_path):
        print(f"Bulk report not found at {bulk_path}")
        return
    if not os.path.exists(whitelist_path):
        print(f"Whitelist report not found at {whitelist_path}")
        return

    # Read whitelist entries into a dictionary keyed by IP.
    whitelist_records = {}
    with open(whitelist_path, newline='', encoding='utf-8') as wf:
        reader = csv.DictReader(wf)
        for row in reader:
            ip = row["IP"].strip()
            whitelist_records[ip] = row

    # Read bulk entries and override with whitelist where applicable.
    filtered_records = []
    with open(bulk_path, newline='', encoding='utf-8') as bf:
        reader = csv.DictReader(bf)
        for row in reader:
            ip = row["IP"].strip()
            # If the IP appears in the whitelist, prefer that record.
            if ip in whitelist_records:
                filtered_records.append(whitelist_records[ip])
            else:
                filtered_records.append(row)

    # Write the filtered bulk report.
    with open(filtered_bulk_path, "w", newline='', encoding='utf-8') as ff:
        fieldnames = ["IP", "Categories", "ReportDate", "Comment"]
        writer = csv.DictWriter(ff, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(filtered_records)

    print(f"Filtered Bulk Report created at: {filtered_bulk_path}")

if __name__ == "__main__":
    output_dir = "output"
    filter_bulk_report(output_dir)

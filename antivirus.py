#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hydra Dragon Antivirus - IP Scanner (fixed)

Key fixes (see commit notes in chat):
 - Enforced hard stop via a supervisor thread (default 55 minutes; configurable).
 - When time limit is hit: stop_event is set, remaining queue items are drained (task_done called)
   so queue.join() unblocks and the program exits promptly.
 - Workers check the elapsed time before making network calls and will abort early.
 - Requests always use configured per-request timeouts so no worker stays blocked longer than that.
 - Cleaner shutdown: session closed, CSV outputs written for all known buckets.
 - Preserved original behaviour and templates.
"""
import os
import re
import string
import sys
import json
import ipaddress
import threading
import queue
import time
import difflib
import requests
import logging
import warnings
import glob
from functools import lru_cache
from datetime import datetime, timezone
from tqdm import tqdm
import csv

# Optional: BeautifulSoup only used for deeper HTML parsing; if missing, scanning still works.
try:
    from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except Exception:
    BeautifulSoup = None

# --- Paths / dirs ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "website", "reports")
INPUT_DIR = os.path.join(BASE_DIR, "website")
LOG_DIR = os.path.join(BASE_DIR, "logs")
SETTINGS_FILE = os.path.join(BASE_DIR, "settings", "settings.json")
DEFAULT_TIME_LIMIT_SECONDS = 55 * 60  # default changed to 55 minutes; can be overridden via settings ScanTimeLimitSeconds
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(INPUT_DIR, exist_ok=True)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "scanner.log")),
        logging.StreamHandler(sys.stdout)
    ]
)

# --- Settings loader ---
@lru_cache(maxsize=1)
def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        logging.error("Settings file not found: %s", SETTINGS_FILE)
        sys.exit(1)
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            settings = json.load(f)
        logging.info("Loaded settings from %s", SETTINGS_FILE)
        return settings
    except Exception as e:
        logging.exception("Failed to read settings.json: %s", e)
        sys.exit(1)

SETTINGS = load_settings()
# derive runtime time limit from settings (seconds). If absent, default to DEFAULT_TIME_LIMIT_SECONDS
TIME_LIMIT_SECONDS = int(SETTINGS.get("ScanTimeLimitSeconds", DEFAULT_TIME_LIMIT_SECONDS))

# --- Globals ---
processed_results = {}  # ip -> { categories:set, references:set, last_comment:str, count:int, processed:bool, status_type:str, similarity:float }
scanner_lock = threading.Lock()

# --- Utility functions ---

def is_valid_public_ip(ip_str):
    """Return True if ip_str is a valid public IPv4/IPv6 address (not private/loopback/link-local/multicast/reserved)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        # exclude non-public
        if getattr(ip_obj, "is_private", False) or getattr(ip_obj, "is_loopback", False) \
           or getattr(ip_obj, "is_link_local", False) or getattr(ip_obj, "is_multicast", False) \
           or getattr(ip_obj, "is_reserved", False):
            return False
        return True
    except Exception:
        return False


def compute_similarity(text1, text2):
    return difflib.SequenceMatcher(None, text1, text2).ratio() * 100

# read rows supporting split files like base_1.csv, base_2.csv...

def read_rows_from_files(base_filepath):
    base_name, extension = os.path.splitext(base_filepath)
    glob_pattern = f"{base_name}_[0-9]*{extension}"
    split_files = glob.glob(glob_pattern)

    def get_part_number(fn):
        try:
            name = os.path.splitext(os.path.basename(fn))[0]
            return int(name.rsplit("_", 1)[-1])
        except Exception:
            return float("inf")

    split_files = [f for f in split_files if get_part_number(f) != float("inf")]
    split_files.sort(key=get_part_number)
    if split_files:
        logging.info("Detected %d split parts for %s", len(split_files), os.path.basename(base_filepath))
        for p in split_files:
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    reader = csv.reader(fh)
                    next(reader, None)  # skip header if present
                    for row in reader:
                        yield row
            except Exception as e:
                logging.error("Error reading split part %s: %s", p, e)
                return
    if os.path.exists(base_filepath):
        try:
            with open(base_filepath, "r", encoding="utf-8") as fh:
                reader = csv.reader(fh)
                next(reader, None)
                for row in reader:
                    yield row
        except Exception as e:
            logging.error("Error reading file %s: %s", base_filepath, e)
    else:
        return

# parse cell like "1.1.1.1,korna | korna2" or "1.1.1.1 | korna" or "1.1.1.1"
_ip_re = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')

def _tokens_from_cell(cell):
    # split on whitespace and punctuation, preserve tokens that might be IPs
    separators = string.whitespace + string.punctuation
    token = ""
    tokens = []
    for ch in cell:
        if ch in separators:
            if token:
                tokens.append(token)
                token = ""
        else:
            token += ch
    if token:
        tokens.append(token)
    return tokens

def parse_cell_for_ip_and_refs(cell):
    """
    Returns list of tuples: (ip, [refs])
    - Supports IPv4 and IPv6 by validating tokens with ipaddress.ip_address()
    - Attempts to attribute nearby text as references (simple heuristic).
    """
    results = []
    if not cell:
        return results

    # split on '|' first to preserve intended ref blocks
    parts = [p.strip() for p in cell.split("|") if p.strip()]
    last_ip = None
    for p in parts:
        # look for any token in part that is a valid IP (v4 or v6)
        tokens = _tokens_from_cell(p)
        found_ip = None
        for t in tokens:
            try:
                ip_obj = ipaddress.ip_address(t)
                # valid IP (v4 or v6)
                found_ip = t
                break
            except Exception:
                continue
        if found_ip:
            # build refs as anything in part after removing the ip token
            after = p.replace(found_ip, "").strip(" ,|")
            refs = [r.strip() for r in re.split(r'[|,;/]+', after) if r.strip()]
            results.append((found_ip, refs))
            last_ip = found_ip
        else:
            # no IP in this segment -> treat as additional ref for last ip
            if last_ip and results:
                last_ip_existing, refs_existing = results[-1]
                if p and p not in refs_existing:
                    refs_existing.append(p)
                    results[-1] = (last_ip_existing, refs_existing)
    return results

# --- Seed loader ---

def load_seeds(settings):
    """ Build seeds list from settings["InputFiles"]. Each seed = {"ip": ip, "category": category, "discovered_url": f"http://{ip}", "references": [...] }.
    Adds "HydraDragonAntivirusSearchEngine" to references for first-seen IPs.
    """
    seeds = []
    seen_ips = set()
    whitelist_ips = set()
    input_files = settings.get("InputFiles", [])
    # 1) collect whitelist IPs
    for file_info in input_files:
        try:
            if file_info.get("category") and file_info.get("category").lower() == "whitelist":
                filepath = os.path.join(INPUT_DIR, file_info.get("filename", ""))
                for row in read_rows_from_files(filepath):
                    if not row:
                        continue
                    cell = row[0].strip() if len(row) > 0 else ""
                    parsed = parse_cell_for_ip_and_refs(cell)
                    if parsed:
                        for ip, _refs in parsed:
                            if is_valid_public_ip(ip):
                                whitelist_ips.add(ip)
                    else:
                        if len(row) > 1:
                            maybe = row[1].strip()
                            m = _ip_re.search(maybe)
                            if m and is_valid_public_ip(m.group(0)):
                                whitelist_ips.add(m.group(0))
        except Exception as e:
            logging.debug("Whitelist load error for %s: %s", file_info.get("filename"), e)
    logging.info("Loaded %d whitelist IPs", len(whitelist_ips))

    # 2) process all input files
    for file_info in input_files:
        category = file_info.get("category", "Unknown")
        filename = file_info.get("filename", "")
        filepath = os.path.join(INPUT_DIR, filename)
        got_any = False
        for row in read_rows_from_files(filepath):
            got_any = True
            if not row:
                continue
            # explicit refs from second column
            explicit_refs = []
            if len(row) > 1 and row[1].strip():
                explicit_refs = [r.strip() for r in row[1].split("|") if r.strip()]
            raw = row[0].strip() if len(row) > 0 else ""
            parsed = parse_cell_for_ip_and_refs(raw)
            if not parsed:
                m = _ip_re.search(raw)
                if m:
                    ip = m.group(0)
                    if not is_valid_public_ip(ip):
                        continue
                    refs = []
                    if explicit_refs:
                        refs.extend(explicit_refs)
                    final_category = "Whitelist" if ip in whitelist_ips else category
                    seed = {"ip": ip, "category": final_category, "discovered_url": f"http://{ip}"}
                    if refs:
                        seed["references"] = refs
                    # first time seen -> add HydraDragon ref
                    if ip not in seen_ips:
                        seed.setdefault("references", []).append("HydraDragonAntivirusSearchEngine")
                    seeds.append(seed)
                    seen_ips.add(ip)
                continue
            for ip, refs_from_cell in parsed:
                if not is_valid_public_ip(ip):
                    continue
                refs = []
                if refs_from_cell:
                    refs.extend(refs_from_cell)
                if explicit_refs:
                    refs.extend(explicit_refs)
                # unique preserve order
                seen_local = set()
                refs_unique = []
                for r in refs:
                    if r and r not in seen_local:
                        seen_local.add(r)
                        refs_unique.append(r)
                final_category = "Whitelist" if ip in whitelist_ips else category
                seed = {"ip": ip, "category": final_category, "discovered_url": f"http://{ip}"}
                if refs_unique:
                    seed["references"] = refs_unique
                if ip not in seen_ips:
                    seed.setdefault("references", []).append("HydraDragonAntivirusSearchEngine")
                seeds.append(seed)
                seen_ips.add(ip)
        if not got_any:
            logging.debug("No rows yielded from %s (missing or empty).", filepath)
    logging.info("Total unique seeds loaded for processing: %d", len(seeds))
    return seeds

# --- Scanner ---
class HeuristicScanner:
    def __init__(self, settings):
        self.settings = settings
        # enforce a reasonable per-request timeout (seconds)
        try:
            self.timeout = max(1, int(settings.get("RequestTimeout", 10)))
        except Exception:
            self.timeout = 10
        self.seed_queue = queue.Queue()
        self.pbar = None
        # initialize realtime buckets from OutputFiles keys
        self.realtime_results = {k: {} for k in settings.get("OutputFiles", {}).keys()}
        self.stop_event = threading.Event()
        self.start_time = None
        self.session = requests.Session()
        self.supervisor_thread = None

    def enqueue_seeds_with_priority(self, seeds, prioritize_by_refs=True, randomize=True, fraction=1.0):
        """Pre-sort and enqueue seeds.
        - prioritize_by_refs: sort descending by number of references
        - randomize: use random tie-breakers and/or shuffle
        - fraction: float in (0,1] to only enqueue that fraction of seeds (top portion after sorting)
        """
        import random
        # work on a shallow copy so we don't mutate caller objects
        seeds_copy = [dict(s) for s in seeds]

        if prioritize_by_refs:
            # attach random tiebreaker
            for s in seeds_copy:
                s.setdefault("references", [])
                s["_rand_tiebreak"] = random.random()
            seeds_copy.sort(key=lambda s: (-len(s.get("references", [])), s["_rand_tiebreak"]))
            for s in seeds_copy:
                s.pop("_rand_tiebreak", None)
            if randomize:
                # small local shuffle among equal-ref-count blocks to avoid strict ordering
                i = 0
                grouped = []
                while i < len(seeds_copy):
                    cnt = len(seeds_copy[i].get("references", []))
                    j = i
                    while j < len(seeds_copy) and len(seeds_copy[j].get("references", [])) == cnt:
                        j += 1
                    block = seeds_copy[i:j]
                    random.shuffle(block)
                    grouped.extend(block)
                    i = j
                seeds_copy = grouped
        else:
            if randomize:
                random.shuffle(seeds_copy)

        # apply fraction (keep top portion)
        try:
            frac = float(fraction)
        except Exception:
            frac = 1.0
        frac = max(0.0, min(1.0, frac))
        if frac < 1.0:
            keep = max(1, int(len(seeds_copy) * frac))
            seeds_copy = seeds_copy[:keep]

        for seed in seeds_copy:
            # ensure we don't enqueue empty seeds
            if seed.get("ip"):
                self.seed_queue.put(seed)

    def _default_processed_entry(self):
        return {
            "categories": set(),
            "references": set(),
            "last_comment": "",
            "count": 0,
            "processed": False,
            "status_type": "up",
            "similarity": 0.0
        }

    def write_csv_target(self, target_key):
        output_files = self.settings.get("OutputFiles", {})
        if target_key not in output_files:
            return
        file_name = output_files[target_key]
        file_path = os.path.join(OUTPUT_DIR, file_name)
        header = "IP,Categories,References,ReportDate,Comment\n"
        try:
            with open(file_path, "w", encoding="utf-8", newline="") as fh:
                fh.write(header)
                # sort by IP for deterministic output
                for ip in sorted(self.realtime_results.get(target_key, {}).keys()):
                    fh.write(self.realtime_results[target_key][ip] + "\n")
        except Exception as e:
            logging.error("Error writing CSV %s: %s", file_path, e)

    def update_realtime_result(self, ip):
        with scanner_lock:
            data = processed_results.get(ip)
            if not data:
                return
            report_date = datetime.now(timezone.utc).isoformat()
            categories = sorted(list(data.get("categories", [])))
            all_categories_str = ",".join(categories)
            refs = sorted(list(data.get("references", [])))
            refs_str = "|".join(refs) if refs else ""
            comment = data.get("last_comment", "").strip()
            count = int(data.get("count", 0))
            is_duplicate = count > 1 and "Whitelist" not in categories
            if is_duplicate:
                comment = comment.replace("Zeroday: Yes", "Zeroday: No")
            status_type = data.get("status_type", "up")
            is_whitelist = ("Whitelist" in categories)
            target_key = "bulk"
            if is_whitelist:
                target_key = "whitelist"
            else:
                if status_type == "potentially_up":
                    target_key = "potentially_up_bulk"
                elif status_type == "potentially_down":
                    target_key = "potentially_down_bulk"
                elif status_type == "winerror":
                    target_key = "winerror_bulk"
            if is_duplicate:
                target_key += "_duplicate"
            # remove ip from any previous buckets
            for key in list(self.realtime_results.keys()):
                if ip in self.realtime_results.get(key, {}):
                    try:
                        del self.realtime_results[key][ip]
                    except KeyError:
                        pass
            # CSV row: IP,"Categories","References",ReportDate,"Comment"
            csv_row = f'{ip},"{all_categories_str}","{refs_str}",{report_date},"{comment}"'
            if target_key not in self.realtime_results:
                self.realtime_results[target_key] = {}
            self.realtime_results[target_key][ip] = csv_row
            # write that target file
            self.write_csv_target(target_key)

    def _drain_queue(self):
        # mark all remaining queued tasks as done (so queue.join() won't block)
        while True:
            try:
                self.seed_queue.get_nowait()
                try:
                    self.seed_queue.task_done()
                except Exception:
                    pass
            except queue.Empty:
                break

    def _supervisor(self):
        # monitor elapsed time and force stop when limit reached
        while not self.stop_event.is_set() and self.start_time is not None:
            elapsed = time.time() - self.start_time
            if elapsed > TIME_LIMIT_SECONDS:
                logging.warning("Scan time exceeded %d seconds (%s). Stopping workers.", TIME_LIMIT_SECONDS, time.ctime())
                self.stop_event.set()
                # drain queue so join() unblocks
                self._drain_queue()
                break
            # sleep a bit to avoid busy-looping
            time.sleep(1)

    def process_seed(self, seed):
        ip = seed.get("ip")
        if not ip:
            return
        initial_category = seed.get("category", "Unknown")
        discovered_url = seed.get("discovered_url", f"http://{ip}")
        references = seed.get("references", [])
        # initialize processed_results entry
        with scanner_lock:
            if ip not in processed_results:
                processed_results[ip] = self._default_processed_entry()
            processed_results[ip]["categories"].add(initial_category)
            for r in references:
                if r:
                    processed_results[ip]["references"].add(r)
            processed_results[ip]["count"] = int(processed_results[ip].get("count", 0)) + 1
        # if already processed before, just update CSV and return
        if processed_results[ip].get("processed"):
            self.update_realtime_result(ip)
            return
        processed_results[ip]["processed"] = True

        # check elapsed time before doing any network work
        if self.start_time and (time.time() - self.start_time > TIME_LIMIT_SECONDS):
            logging.warning("Time limit reached before processing %s, skipping.", ip)
            # set stop flag and avoid making requests
            self.stop_event.set()
            return

        try:
            # make the HTTP request with the enforced timeout
            response = self.session.get(f"http://{ip}", timeout=self.timeout, allow_redirects=True)
            status_code = response.status_code
            content = response.content or b""

            # ZeroDay binary check
            if status_code == 200 and content and (content.startswith(b'MZ') or content.startswith(b'\x7fELF')):
                sig = "MZ" if content.startswith(b'MZ') else "ELF"
                comment = f"ZeroDay Executable detected ({sig} signature)"
                with scanner_lock:
                    processed_results[ip]["categories"].add("Malware")
                    processed_results[ip]["last_comment"] = comment
                    processed_results[ip]["status_type"] = "up"
                self.update_realtime_result(ip)
                return

            # attempt to get text for html parsing and ip extraction
            try:
                base_text = response.text
            except Exception:
                base_text = ""

            # discover ips in content
            found_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', base_text)
            for new_ip in found_ips:
                if new_ip != ip and is_valid_public_ip(new_ip):
                    with scanner_lock:
                        if new_ip not in processed_results:
                            processed_results[new_ip] = self._default_processed_entry()
                            processed_results[new_ip]["categories"].add("Heuristic")
                            processed_results[new_ip]["references"].add("HydraDragonAntivirusSearchEngine")
                            processed_results[new_ip]["count"] = 1
                    new_seed = {"ip": new_ip, "category": "Heuristic", "discovered_url": f"http://{new_ip}", "references": ["HydraDragonAntivirusSearchEngine"]}
                    # enqueue discovered IPs but respect stop_event
                    if not self.stop_event.is_set():
                        self.seed_queue.put(new_seed)
                        if self.pbar:
                            try:
                                self.pbar.total += 1
                                self.pbar.refresh()
                            except Exception:
                                pass

            # determine status/comment based on HTTP codes from settings
            code_str = str(status_code)
            http_up = [c.strip() for c in self.settings.get("HTTPUpCodes", "").split(",") if c.strip()]
            http_potentially_up = [c.strip() for c in self.settings.get("HTTPPotentiallyUpCodes", "").split(",") if c.strip()]
            http_potentially_down = [c.strip() for c in self.settings.get("HTTPPotentiallyDownCodes", "").split(",") if c.strip()]
            status_type = "up"
            template = self.settings.get("CommentTemplateNoZeroday", "")
            if code_str in http_up:
                template = self.settings.get("CommentTemplateZeroday", "") if status_code != 200 else self.settings.get("CommentTemplateZerodayStatus200", "")
                status_type = "up"
            elif code_str in http_potentially_up:
                template = self.settings.get("CommentTemplateNoZeroday", "")
                status_type = "potentially_up"
            elif code_str in http_potentially_down:
                template = self.settings.get("CommentTemplateNoZeroday", "")
                status_type = "potentially_down"
            else:
                template = self.settings.get("CommentTemplateNoZeroday", "")
                status_type = "up"

            try:
                comment = template.format(ip=ip, discovered_url=discovered_url, verdict=initial_category, status=status_code, similarity=0.0)
            except Exception:
                comment = f"{ip} - status {status_code} - {initial_category}"

        except requests.exceptions.RequestException as e:
            status_type = "winerror"
            comment_template = self.settings.get("CommentTemplateNoZeroday", "{ip} - Error: {err}")
            try:
                comment = comment_template.format(ip=ip, discovered_url=discovered_url, verdict=initial_category, status=f"Error: {type(e).__name__}", err=type(e).__name__)
            except Exception:
                comment = f"Error contacting {ip}: {type(e).__name__}"

        # persist results and update CSV
        with scanner_lock:
            processed_results[ip]["status_type"] = status_type
            processed_results[ip]["last_comment"] = comment
            processed_results[ip]["similarity"] = float(processed_results[ip].get("similarity", 0.0))
        self.update_realtime_result(ip)

    def worker(self):
        while not self.stop_event.is_set():
            try:
                seed = self.seed_queue.get(timeout=1)
            except queue.Empty:
                # if stop requested, break; otherwise keep waiting
                if self.stop_event.is_set():
                    break
                continue
            # If stop_event set after getting the seed, mark task done and stop
            if self.stop_event.is_set():
                try:
                    self.seed_queue.task_done()
                except Exception:
                    pass
                break
            try:
                self.process_seed(seed)
            finally:
                try:
                    self.seed_queue.task_done()
                except Exception:
                    pass
            if self.pbar:
                try:
                    self.pbar.update(1)
                except Exception:
                    pass

    def run(self, seeds):
        self.start_time = time.time()
        logging.info("Initializing scan...")
        # prepare seeds and optionally prioritize/randomize before enqueueing
        seeds_prepared = []
        for seed in seeds:
            ip = seed.get("ip")
            if not ip:
                continue
            with scanner_lock:
                if ip not in processed_results:
                    processed_results[ip] = self._default_processed_entry()
                processed_results[ip]["categories"].add(seed.get("category", "Unknown"))
                for ref in seed.get("references", []):
                    if ref:
                        processed_results[ip]["references"].add(ref)
                processed_results[ip]["count"] = int(processed_results[ip].get("count", 0)) + 1
            seeds_prepared.append(seed)

        # Enqueue with prioritization / randomization / fraction, controlled by settings
        prioritize = bool(self.settings.get("PrioritizeByReferences", True))
        randomize_q = bool(self.settings.get("RandomizeQueue", True))
        fraction = float(self.settings.get("ScanFraction", 1.0))
        self.enqueue_seeds_with_priority(
            seeds_prepared,
            prioritize_by_refs=prioritize,
            randomize=randomize_q,
            fraction=fraction
        )

        # after enqueueing, count how many items are in the queue
        initial_count = self.seed_queue.qsize()
        if initial_count == 0:
            logging.warning("No seeds to scan.")
            return

        # progress bar
        self.pbar = tqdm(total=initial_count, desc="Scanning IPs", unit="ip")

        # spawn supervisor
        self.supervisor_thread = threading.Thread(target=self._supervisor, daemon=True)
        self.supervisor_thread.start()

        # spawn worker threads
        try:
            max_threads = max(1, int(self.settings.get("MaxThreads", 10)))
        except Exception:
            max_threads = 10
        num_threads = min(max_threads, max(1, initial_count))
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            threads.append(t)

        try:
            # join the queue (this will unblock because supervisor drains and sets stop_event on timeout)
            self.seed_queue.join()
        except KeyboardInterrupt:
            logging.warning("KeyboardInterrupt: stopping.")
            self.stop_event.set()
            # drain queue in case
            self._drain_queue()

        # ensure stop flag so workers can exit
        self.stop_event.set()

        # wait for threads to finish
        for t in threads:
            t.join(timeout=2)
        if self.supervisor_thread:
            self.supervisor_thread.join(timeout=2)

        if self.pbar:
            try:
                self.pbar.close()
            except Exception:
                pass

        # final write of all outputs to ensure up-to-date CSVs
        for key in list(self.realtime_results.keys()):
            try:
                self.write_csv_target(key)
            except Exception:
                pass

        # close session cleanly
        try:
            self.session.close()
        except Exception:
            pass

        logging.info("Scan completed or stopped. Reports written to %s", OUTPUT_DIR)

# --- Main ---

def main():
    logging.info("--- Hydra Dragon Antivirus Search Engine Initializing ---")
    seeds = load_seeds(SETTINGS)
    if not seeds:
        logging.error("No seeds loaded. Exiting.")
        sys.exit(1)
    scanner = HeuristicScanner(SETTINGS)
    scanner.run(seeds)
    logging.info("--- Shutdown ---")


if __name__ == "__main__":
    main()

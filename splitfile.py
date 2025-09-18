#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import argparse
import logging

# --- Basic Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "file_splitter.log")),
        logging.StreamHandler()
    ]
)

def split_file(file_path, chunk_size_mb=99.5):
    """
    Splits a large text file (like a CSV) into smaller chunks based on size,
    without breaking lines. Ensures no chunk exceeds chunk_size_mb.
    """
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return

    chunk_size_bytes = int(chunk_size_mb * 1024 * 1024)

    # Quick check: if file is already small enough, do nothing.
    file_size = os.path.getsize(file_path)
    if file_size <= chunk_size_bytes:
        logging.info(f"File '{os.path.basename(file_path)}' is smaller than {chunk_size_mb}MB. No splitting needed.")
        return

    logging.info(f"Splitting '{os.path.basename(file_path)}' into chunks strictly under {chunk_size_mb}MB.")

    try:
        # Open in text mode (utf-8). tell()/seek() pairs are used to backtrack to start of a line.
        with open(file_path, 'r', encoding='utf-8', newline='') as f_in:
            header = f_in.readline()
            if header is None:
                logging.error("Failed to read header or file is empty.")
                return

            header_size = len(header.encode('utf-8'))
            if header_size >= chunk_size_bytes:
                logging.error("Header alone is larger than the configured chunk size. Increase chunk size.")
                return

            part_num = 1
            base_name, extension = os.path.splitext(file_path)

            while True:
                output_path = f"{base_name}_{part_num}{extension}"
                lines_written_in_chunk = 0
                current_chunk_size = header_size

                with open(output_path, 'w', encoding='utf-8', newline='') as f_out:
                    # write header first
                    f_out.write(header)

                    # read lines and ensure we don't exceed chunk_size_bytes
                    while True:
                        pos_before_line = f_in.tell()
                        line = f_in.readline()
                        if not line:  # EOF
                            break

                        line_size = len(line.encode('utf-8'))
                        # If adding this line would exceed the limit, rewind and stop this chunk.
                        if current_chunk_size + line_size > chunk_size_bytes:
                            # Seek back to start of this line so next chunk will read it
                            f_in.seek(pos_before_line)
                            break

                        f_out.write(line)
                        current_chunk_size += line_size
                        lines_written_in_chunk += 1

                # If we didn't write any data lines (only header), remove the empty chunk and finish.
                if lines_written_in_chunk == 0:
                    try:
                        os.remove(output_path)
                    except OSError:
                        pass
                    break

                final_chunk_size_mb = os.path.getsize(output_path) / (1024 * 1024)
                logging.info(f"Created chunk: {os.path.basename(output_path)} ({final_chunk_size_mb:.2f} MB)")
                part_num += 1

                # If we've reached EOF, break out of the loop.
                if f_in.tell() >= os.fstat(f_in.fileno()).st_size:
                    break

        logging.info("File splitting complete.")
    except Exception as e:
        logging.error(f"An error occurred during file splitting: {e}")


def main():
    """Main execution function for the command-line interface."""
    parser = argparse.ArgumentParser(
        description="A utility to split large files for the Hydra scanner. "
                    "Example: python file_splitter.py ./website/my_large_report.csv --chunk-size 99.5"
    )
    parser.add_argument("file", help="The path to the file to split.")
    parser.add_argument(
        "--chunk-size",
        dest="chunk_size",
        type=float,
        default=99.5,
        help="The maximum chunk size in megabytes (MB). Default is 99.5."
    )
    args = parser.parse_args()

    split_file(args.file, args.chunk_size)


if __name__ == "__main__":
    main()

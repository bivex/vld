#!/usr/bin/env python3
"""
Batch dump SG-encrypted PHP files using VLD + ixed loader on PHP 8.3.

Usage:
    python3 sg_batch_dump.py /path/to/files --output /path/to/dumps

Requirements:
    - PHP 8.3 with ixed.8.3.dar (SG loader)
    - VLD module (renamed to avoid SG detection)
"""

import subprocess
import sys
import os
import re
import time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

PHP_BIN = "/opt/homebrew/opt/php@8.3/bin/php"
IXED_SO = "/tmp/ixed.8.3.dar"
VLD_SO = "/Volumes/External/Code/backup/ymgvld/modules/vld.so"


def dump_sg_file(filepath: str, output_dir: str) -> dict:
    """Dump a single SG-encrypted PHP file."""
    filepath = Path(filepath)
    out_path = Path(output_dir) / filepath.name.replace('.php', '.dump.txt')

    if out_path.exists():
        return {"file": str(filepath), "status": "cached", "lines": 0}

    try:
        result = subprocess.run(
            [
                PHP_BIN,
                "-d", f"extension={IXED_SO}",
                "-d", f"extension={VLD_SO}",
                "-d", "xdc.active=1",
                "-d", "xdc.execute=1",
                str(filepath),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(filepath.parent),
        )

        output = result.stderr
        if not output:
            output = result.stdout

        # Check for decrypted content (Class or Function markers)
        has_decrypted = bool(re.search(r'^Class\s+|^Function\s+', output, re.MULTILINE))

        if not has_decrypted and result.returncode != 0:
            return {"file": str(filepath), "status": "error", "lines": 0,
                    "error": f"exit={result.returncode}"}

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output)

        lines = output.count('\n')
        functions = len(re.findall(r'^Function\s+', output, re.MULTILINE))
        classes = len(re.findall(r'^Class\s+', output, re.MULTILINE))

        return {
            "file": str(filepath),
 "status": "ok",
            "lines": lines,
            "functions": functions,
            "classes": classes,
            "decrypted": has_decrypted,
        }

    except subprocess.TimeoutExpired:
        return {"file": str(filepath), "status": "timeout", "lines": 0}
    except Exception as e:
        return {"file": str(filepath), "status": "error", "lines": 0, "error": str(e)}


def main():
    if len(sys.argv) < 2:
        print("Usage: sg_batch_dump.py <directory> [--output <dir>] [--workers N]")
        sys.exit(1)

    source_dir = sys.argv[1]
    output_dir = "/tmp/sg_dumps"
    workers = 4

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--output" and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--workers" and i + 1 < len(sys.argv):
            workers = int(sys.argv[i + 1])
            i += 2
        else:
            i += 1

    # Find all SG-encrypted files
    source = Path(source_dir)
    sg_files = []
    for f in source.rglob("*.php"):
        try:
            with open(f) as fh:
                head = fh.read(200)
            if 'sg_load' in head:
                sg_files.append(f)
        except:
            pass

    print(f"Found {len(sg_files)} SG-encrypted files")
    print(f"Output: {output_dir}")
    print(f"Workers: {workers}")
    print()

    stats = {"ok": 0, "cached": 0, "error": 0, "timeout": 0}
    total_functions = 0
    total_classes = 0
    t0 = time.time()

    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(dump_sg_file, str(f), output_dir): f for f in sg_files}

        for i, future in enumerate(as_completed(futures), 1):
            r = future.result()
            status = r["status"]
            stats[status] = stats.get(status, 0) + 1

            if status == "ok":
                total_functions += r.get("functions", 0)
                total_classes += r.get("classes", 0)
                marker = "+" if r.get("decrypted") else "-"
            elif status == "cached":
                marker = "."
            else:
                marker = "!"

            if i % 50 == 0 or i == len(sg_files):
                elapsed = time.time() - t0
                rate = i / elapsed if elapsed > 0 else 0
                print(f"  [{i}/{len(sg_files)}] {rate:.1f} files/s | "
                      f"ok={stats['ok']} err={stats['error']} "
                      f"fn={total_functions} cls={total_classes}")

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.1f}s")
    print(f"  OK: {stats['ok']}, Cached: {stats['cached']}, "
          f"Errors: {stats['error']}, Timeouts: {stats['timeout']}")
    print(f"  Total functions: {total_functions}, classes: {total_classes}")


if __name__ == "__main__":
    main()

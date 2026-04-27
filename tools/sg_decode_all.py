#!/usr/bin/env python3
"""
sg_decode_all.py — Full pipeline: SG-encrypted PHP → VLD dump → reconstructed PHP

Takes the backup directory with SourceGuardian-encrypted PHP files,
dumps opcodes via PHP+VLD, reconstructs clean PHP source, and outputs
to a target directory preserving the original folder structure.

Usage:
    python3 sg_decode_all.py /path/to/backup/application /path/to/output [--skip-dump] [--workers 4]

Requirements:
    - PHP 8.3 with SG loader (ixed.8.3.dar)
    - ymgvld extension built for PHP 8.3
"""

import os
import sys
import argparse
import subprocess
import shutil
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

# ── Config ──────────────────────────────────────────────────────────────────

PHP_BIN = "/opt/homebrew/opt/php@8.3/bin/php"
SG_LOADER = "/tmp/ixed.8.3.dar"
VLD_SO = "/Volumes/External/Code/backup/ymgvld/modules/vld.so"
DUMP_DIR = "/tmp/sg_dumps"

# VLD dump command: execute=1 to hook runtime (after SG decrypt), active=1 to enable
VLD_CMD = (
    f"{PHP_BIN}"
    f" -d extension={SG_LOADER}"
    f" -d extension={VLD_SO}"
    f" -d vld.active=1"
    f" -d vld.execute=1"
    f" -d vld.dump_paths=0"
)


def is_sg_file(filepath: str) -> bool:
    """Check if a PHP file is SourceGuardian-encrypted."""
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read(500)
        return "sg_load" in content
    except Exception:
        return False


def dump_file(filepath: str, dump_dir: str) -> str:
    """Run VLD dump on a single SG-encrypted file. Returns dump path."""
    rel = os.path.relpath(filepath)
    basename = Path(filepath).stem
    dump_path = os.path.join(dump_dir, f"{basename}.dump.txt")

    if os.path.exists(dump_path) and os.path.getsize(dump_path) > 100:
        return dump_path

    cmd = f"{VLD_CMD} {filepath}"
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=30
    )
    output = result.stderr + result.stdout

    if len(output) > 100:
        with open(dump_path, "w") as f:
            f.write(output)
        return dump_path

    return ""


def extract_original_path(dump_path: str) -> str:
    """Extract original file path from VLD dump."""
    try:
        with open(dump_path, "r", errors="ignore") as f:
            for line in f:
                if line.startswith("filename:"):
                    return line.split("filename:")[1].strip()
    except Exception:
        pass
    return ""


def reconstruct_file(dump_path: str) -> tuple:
    """Reconstruct PHP from dump. Returns (dump_path, php_code or None)."""
    reconstructor = "/Volumes/External/Code/backup/vld-upstream/tools/sg_reconstructor_advanced.py"
    try:
        result = subprocess.run(
            ["env", "-u", "PYTHONHOME", "-u", "PYTHONPATH",
             "/usr/bin/python3", reconstructor, dump_path],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout.strip():
            return (dump_path, result.stdout)
    except Exception as e:
        print(f"  Error reconstructing {dump_path}: {e}", file=sys.stderr)
    return (dump_path, None)


def main():
    parser = argparse.ArgumentParser(description="SG decrypt + reconstruct pipeline")
    parser.add_argument("source", help="Source directory with SG-encrypted PHP files")
    parser.add_argument("output", help="Output directory for clean PHP files")
    parser.add_argument("--skip-dump", action="store_true",
                        help="Skip VLD dumping (reuse existing dumps)")
    parser.add_argument("--skip-reconstruct", action="store_true",
                        help="Skip reconstruction (only copy non-SG files)")
    parser.add_argument("--workers", type=int, default=4,
                        help="Number of parallel workers for dumping")
    args = parser.parse_args()

    source = os.path.abspath(args.source)
    output = os.path.abspath(args.output)

    if not os.path.isdir(source):
        print(f"Error: source directory not found: {source}")
        sys.exit(1)

    os.makedirs(output, exist_ok=True)
    os.makedirs(DUMP_DIR, exist_ok=True)

    # ── Step 1: Collect all files ──────────────────────────────────────────

    print("Scanning files...")
    sg_files = []
    plain_files = []
    non_php_files = []

    for root, dirs, files in os.walk(source):
        for fn in files:
            full = os.path.join(root, fn)
            if fn.endswith(".php"):
                if is_sg_file(full):
                    sg_files.append(full)
                else:
                    plain_files.append(full)
            else:
                non_php_files.append(full)

    print(f"  SG-encrypted PHP: {len(sg_files)}")
    print(f"  Plain PHP:        {len(plain_files)}")
    print(f"  Non-PHP files:    {len(non_php_files)}")

    # ── Step 2: Copy plain files (preserving structure) ────────────────────

    print("\nCopying plain files...")
    for fpath in plain_files + non_php_files:
        rel = os.path.relpath(fpath, source)
        dest = os.path.join(output, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(fpath, dest)
    print(f"  Copied {len(plain_files) + len(non_php_files)} files")

    if args.skip_reconstruct:
        print("\nDone (skip-reconstruct mode). Only plain files copied.")
        return

    # ── Step 3: VLD dump SG files ─────────────────────────────────────────

    if not args.skip_dump:
        print(f"\nDumping {len(sg_files)} SG files with {args.workers} workers...")
        done = 0
        failed = 0

        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = {
                pool.submit(dump_file, f, DUMP_DIR): f for f in sg_files
            }
            for fut in as_completed(futures):
                done += 1
                result = fut.result()
                if not result:
                    failed += 1
                if done % 100 == 0 or done == len(sg_files):
                    print(f"  {done}/{len(sg_files)} dumped ({failed} failed)")

        print(f"  Dumped: {done - failed}, Failed: {failed}")
    else:
        print("\nSkipping dump step (reusing existing dumps)")

    # ── Step 4: Reconstruct PHP from dumps ─────────────────────────────────

    print("\nReconstructing PHP files...")
    dump_files = [f for f in os.listdir(DUMP_DIR) if f.endswith(".dump.txt")]
    print(f"  Found {len(dump_files)} dump files")

    # Build mapping: original_path → dump_path
    path_map = {}
    for df in dump_files:
        dump_path = os.path.join(DUMP_DIR, df)
        orig = extract_original_path(dump_path)
        if orig:
            rel = os.path.relpath(orig, source)
            path_map[rel] = dump_path

    print(f"  Mapped {len(path_map)} dumps to original paths")

    # Reconstruct each dump to its correct output location
    reconstructor = "/Volumes/External/Code/backup/vld-upstream/tools/sg_reconstructor_advanced.py"
    ok = 0
    empty = 0
    errors = 0

    for rel_path, dump_path in sorted(path_map.items()):
        dest = os.path.join(output, rel_path)
        os.makedirs(os.path.dirname(dest), exist_ok=True)

        try:
            result = subprocess.run(
                ["env", "-u", "PYTHONHOME", "-u", "PYTHONPATH",
                 "/usr/bin/python3", reconstructor, dump_path],
                capture_output=True, text=True, timeout=15
            )
            code = result.stdout
            if code and len(code.strip()) > 10:
                with open(dest, "w") as f:
                    f.write(code)
                ok += 1
            else:
                # Empty result — write placeholder
                with open(dest, "w") as f:
                    f.write("<?php\n// [SG] Decryption produced no output\n")
                empty += 1
        except Exception as e:
            errors += 1
            if errors <= 5:
                print(f"  Error: {rel_path}: {e}")

        total = ok + empty + errors
        if total % 200 == 0:
            print(f"  {total}/{len(path_map)} processed (ok={ok}, empty={empty}, err={errors})")

    # Handle SG files without dumps (no class/function content)
    for fpath in sg_files:
        rel = os.path.relpath(fpath, source)
        dest = os.path.join(output, rel)
        if not os.path.exists(dest):
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w") as f:
                f.write("<?php\n// [SG] No dump available\n")
            empty += 1

    print(f"\n{'='*50}")
    print(f"RESULTS")
    print(f"{'='*50}")
    print(f"  Reconstructed: {ok}")
    print(f"  Empty/no data: {empty}")
    print(f"  Errors:        {errors}")
    print(f"  Plain copied:  {len(plain_files)}")
    print(f"  Non-PHP copied:{len(non_php_files)}")
    print(f"  Output:        {output}")

    # Quick syntax check
    print(f"\nRunning syntax check...")
    check = subprocess.run(
        f'find "{output}" -name "*.php" -type f '
        f'-exec {PHP_BIN} -l {{}} \\; 2>&1 '
        f'| grep -v "No syntax errors" | wc -l',
        shell=True, capture_output=True, text=True
    )
    err_count = check.stdout.strip()
    total_php = ok + empty + len(plain_files)
    clean = total_php - int(err_count) if err_count.isdigit() else "?"
    print(f"  Files with issues: {err_count}")
    print(f"  Estimated clean:   {clean}/{total_php}")


if __name__ == "__main__":
    main()

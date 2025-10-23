#!/usr/bin/env python3
"""
Step 2 — Enrich domain|ip pairs with hoster info via PyTricia

Input:  gzip files from Step 1 (lines: "domain|ip")
Output: text files (lines: "domain | ip | org")
"""

import os
import gzip
import logging
import argparse
from typing import List, Tuple, Optional
from glob import glob
from concurrent.futures import ProcessPoolExecutor, as_completed

import pytricia
import csv
import ast

try:
    import yaml
except ImportError:
    yaml = None

from hosterbenchmark.feeds.parsers import load_hosters  # reuse existing logic


# --------------------------------
# Logging
# --------------------------------
LOG_FORMAT = "%(asctime)s %(levelname)s: %(message)s"
logger = logging.getLogger("step2.enrich")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(_handler)


# --------------------------------
# Main per-file processing
# --------------------------------
def process_file(path: str, out_dir: str, ranges: List[Tuple[str, str]]) -> dict:
    """Enrich a single .gz file from Step 1"""
    base = os.path.basename(path)
    out_path = os.path.join(out_dir, f"step3_enriched_{base.replace('.gz', '.txt')}")
    stats = {"file": base, "lines": 0, "written": 0, "errors": 0, "missing_ip": 0}

    pt = pytricia.PyTricia()
    for cidr, org in ranges:
        try:
            pt[cidr] = org
        except Exception as e:
            logger.debug(f"Invalid CIDR {cidr} skipped: {e}")

    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fin, \
             open(out_path, "w", encoding="utf-8") as fout:

            for line in fin:
                stats["lines"] += 1
                line = line.strip()
                if not line or "|" not in line:
                    continue
                try:
                    domain, ip = [x.strip() for x in line.split("|", 1)]
                    org = pt.get(ip) or "UNKNOWN"
                    fout.write(f"{domain} | {ip} | {org}\n")
                    stats["written"] += 1
                except Exception:
                    stats["errors"] += 1
                    continue

    except Exception as e:
        logger.exception(f"Failed to process {base}: {e}")
        stats["errors"] += 1

    return stats


# --------------------------------
# Glob expand
# --------------------------------
def _expand_glob(pattern: str) -> List[str]:
    files = sorted(glob(pattern))
    return [f for f in files if os.path.isfile(f)]


# --------------------------------
# From CLI or config
# --------------------------------
def enrich_pairs_from_args(input_glob: str, hosters_path: str, out_dir: str, processes: int = 1) -> None:
    os.makedirs(out_dir, exist_ok=True)
    files = _expand_glob(input_glob)
    if not files:
        logger.warning(f"No input files matched pattern: {input_glob}")
        return

    logger.info(f"Step2: enriching {len(files)} files with {processes} process(es)")

    hosters = load_hosters(hosters_path)
    ranges = [(cidr, org) for org, cidrs in hosters.items() for cidr in cidrs]

    futs = []
    with ProcessPoolExecutor(max_workers=processes) as ex:
        for f in files:
            futs.append(ex.submit(process_file, f, out_dir, ranges))

        for fu in as_completed(futs):
            st = fu.result()
            logger.info(f"[{st['file']}] lines={st['lines']} written={st['written']} errors={st['errors']}")

    logger.info("Step2: done")


def _load_yaml_config(cfg_path: str) -> dict:
    if yaml is None:
        raise RuntimeError("PyYAML not installed; install pyyaml or pass CLI flags instead.")
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def enrich_pairs(config_path: Optional[str] = None) -> None:
    """
    Library entrypoint (used by CLI runner).
    Reads paths from pipeline.yaml.
    """
    if not config_path:
        raise ValueError("config_path is required when calling enrich_pairs() directly")

    cfg = _load_yaml_config(config_path)
    paths = cfg.get("paths", {})
    params = cfg.get("params", {})

    input_glob = paths.get("step1_out_dir", "") + "/2lds_*.gz"
    out_dir = paths.get("step1_out_dir", "")  # write back to same dir (for now)
    hosters_path = cfg.get("hosters_file")
    processes = int(params.get("processes", 1))

    if not hosters_path or not input_glob:
        raise ValueError("Missing paths.step1_out_dir or hosters_file in pipeline config")

    enrich_pairs_from_args(input_glob, hosters_path, out_dir, processes)


def main():
    ap = argparse.ArgumentParser(description="Step 2: Enrich domain|ip pairs with hoster info")
    ap.add_argument("--input-glob", help='Glob for Step 1 output, e.g. "data/work/2lds_*.gz"')
    ap.add_argument("--hosters", required=False, help='CIDR→org CSV/YAML/pipe file')
    ap.add_argument("--out-dir", help='Output directory (e.g. data/work/)')
    ap.add_argument("--processes", type=int, default=1, help="Parallel processes")
    ap.add_argument("--config", help="Pipeline YAML config")
    args = ap.parse_args()

    logger.setLevel(logging.INFO)

    if args.config:
        enrich_pairs(args.config)
        return

    if not args.input_glob or not args.hosters or not args.out_dir:
        ap.error("Either --config or all of --input-glob, --hosters, and --out-dir must be provided.")

    enrich_pairs_from_args(args.input_glob, args.hosters, args.out_dir, args.processes)


if __name__ == "__main__":
    main()

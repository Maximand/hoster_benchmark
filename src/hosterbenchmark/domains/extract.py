# src/hosterbench/domains/extract.py
#!/usr/bin/env python3
"""
Step 1 — DNSDB extractor
Reads gzipped JSONL DNSDB files with keys like {"rrname": "...", "rdata": ["IP", ...]}
and emits gzipped lines: "<registrable_domain>|<ipv4>"

- Validates FQDN and IPv4s
- Uses tld.get_fld to keep the full registrable domain (e.g., example.co.uk)
- Parallel per-file processing
- Can be driven by CLI flags or a pipeline YAML

Examples:
  python -m hosterbench.domains.extract \
    --glob "/data/people/max/dnsdb_2025/*.gz" \
    --out-dir "data/work/2ld_step1_output" \
    --processes 16

  python -m hosterbench.domains.extract --config config/pipeline.yaml
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import os
import re
import socket
from concurrent.futures import ProcessPoolExecutor, as_completed
from glob import glob
from typing import Iterable, List, Optional

try:
    import yaml  # optional; only needed if --config is used
except Exception:
    yaml = None

from tld import get_fld

# ----------------------------
# Logging
# ----------------------------
LOG_FORMAT = "%(asctime)s %(levelname)s: %(message)s"
logger = logging.getLogger("step1.extract")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(_handler)

# ----------------------------
# DNS label validation (RFC 1035-ish)
# ----------------------------
ALLOWED_HOSTNAME_RE = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)


def is_valid_hostname(hostname: str) -> bool:
    """Check all parts of the hostname match allowed DNS labels."""
    hostname = (hostname or "").strip().rstrip(".")
    if not hostname or ".." in hostname:
        return False
    parts = hostname.split(".")
    return all(ALLOWED_HOSTNAME_RE.match(p) for p in parts)


def parse_rdata_ips(rdata) -> List[str]:
    """Best-effort extraction of IPv4s from the DNSDB rdata field."""
    out = []
    if isinstance(rdata, list):
        cand = rdata
    elif isinstance(rdata, str):
        cand = [rdata]
    else:
        cand = []

    for x in cand:
        try:
            s = str(x).strip()
            socket.inet_aton(s)  # raises if not IPv4
            out.append(s)
        except Exception:
            continue
    return out


def fqdn_to_registrable(fqdn: str) -> Optional[str]:
    """Return registrable domain (eTLD+1) or None if extraction fails."""
    fqdn = (fqdn or "").strip().rstrip(".")
    if not fqdn:
        return None
    try:
        # CRITICAL FIX: keep the full registrable domain
        return get_fld(f"http://{fqdn}", fix_protocol=True)
    except Exception:
        return None


def _process_one_file(in_path: str, out_dir: str) -> dict:
    """
    Worker: process a single gz JSONL file.
    Writes gz output: out_dir / f"2lds_{basename}"
    Returns stats dict.
    """
    base = os.path.basename(in_path)
    # Preserve .gz and prefix with 2lds_
    out_path = os.path.join(out_dir, f"2lds_{base}")

    stats = {"file": base, "lines": 0, "written": 0, "skipped_no_fqdn": 0,
             "skipped_bad_domain": 0, "skipped_no_ips": 0, "errors": 0}

    try:
        with gzip.open(in_path, "rt", encoding="utf-8", errors="replace") as fin, \
             gzip.open(out_path, "wt", encoding="utf-8") as fout:

            for line in fin:
                stats["lines"] += 1
                try:
                    obj = json.loads(line)
                except Exception:
                    stats["errors"] += 1
                    continue

                fqdn = (obj.get("rrname") or "").strip().rstrip(".")
                if not fqdn or "|" in fqdn:
                    stats["skipped_no_fqdn"] += 1
                    continue

                domain = fqdn_to_registrable(fqdn)
                if not domain or not is_valid_hostname(domain):
                    stats["skipped_bad_domain"] += 1
                    continue

                ips = parse_rdata_ips(obj.get("rdata"))
                if not ips:
                    stats["skipped_no_ips"] += 1
                    continue

                for ip in ips:
                    # inet_aton already validated in parse_rdata_ips; keep a tiny guard
                    try:
                        socket.inet_aton(ip)
                    except Exception:
                        continue
                    fout.write(f"{domain}|{ip}\n")
                    stats["written"] += 1

    except Exception as e:
        logger.exception(f"[{base}] Fatal error: {e}")
        stats["errors"] += 1

    return stats


def _expand_glob(pattern: str) -> List[str]:
    files = sorted(glob(pattern))
    return [f for f in files if os.path.isfile(f)]


def extract_dnsdb_from_args(glob_pat: str, out_dir: str, processes: int = 1) -> None:
    os.makedirs(out_dir, exist_ok=True)
    files = _expand_glob(glob_pat)
    if not files:
        logger.warning(f"No input files matched pattern: {glob_pat}")
        return

    logger.info(f"Step1: extracting from {len(files)} files using {processes} process(es)")
    futs = []
    with ProcessPoolExecutor(max_workers=processes) as ex:
        for f in files:
            futs.append(ex.submit(_process_one_file, f, out_dir))

        total_written = 0
        for fu in as_completed(futs):
            st = fu.result()
            total_written += st["written"]
            logger.info(
                f"[{st['file']}] lines={st['lines']} written={st['written']} "
                f"no_fqdn={st['skipped_no_fqdn']} bad_domain={st['skipped_bad_domain']} "
                f"no_ips={st['skipped_no_ips']} errors={st['errors']}"
            )

    logger.info("Step1: done")


def _load_yaml_config(cfg_path: str) -> dict:
    if yaml is None:
        raise RuntimeError("PyYAML not installed; install pyyaml or pass CLI flags instead.")
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def extract_dnsdb(config_path: Optional[str] = None) -> None:
    """
    Library entrypoint (used by the unified CLI).
    Reads from pipeline YAML if provided, else raises.
    """
    if not config_path:
        raise ValueError("config_path is required when calling extract_dnsdb() directly")

    cfg = _load_yaml_config(config_path)
    paths = cfg.get("paths", {})
    params = cfg.get("params", {})

    glob_pat = paths.get("dnsdb_glob")
    out_dir = paths.get("step1_out_dir") or paths.get("work_dir") or "data/work/2ld_step1_output"
    processes = int(params.get("processes", 1))

    if not glob_pat:
        raise ValueError("pipeline.yaml missing paths.dnsdb_glob")

    extract_dnsdb_from_args(glob_pat, out_dir, processes)


def main():
    ap = argparse.ArgumentParser(description="Step1: Extract domain|ip from DNSDB JSONL gz files.")
    ap.add_argument("--glob", help='Input glob for gz files, e.g. "/data/dnsdb/*.gz"')
    ap.add_argument("--out-dir", help='Output directory (writes "2lds_<file>.gz")')
    ap.add_argument("--processes", type=int, default=1, help="Parallel processes (per-file)")
    ap.add_argument("--config", help="Pipeline YAML (overrides flags if set)")
    ap.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = ap.parse_args()

    logger.setLevel(getattr(logging, args.log_level))

    if args.config:
        extract_dnsdb(args.config)
        return

    if not args.glob or not args.out_dir:
        ap.error("Either provide --config or both --glob and --out-dir.")

    extract_dnsdb_from_args(args.glob, args.out_dir, args.processes)


if __name__ == "__main__":
    main()

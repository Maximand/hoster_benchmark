#!/usr/bin/env python3
"""
Step 5 — Ingest IP-only abuse feeds and count hits per hoster.

Inputs (from pipeline.yaml):
  - feeds_file: path to YAML with a 'feeds:' list of {name, path}
  - hosters_file: path to hoster/CIDR mapping (MaxMind-derived CSV/pipe)
  - paths.lmdb_dir: directory for LMDB environment

Also carries forward Step 4 capacity metrics by reading:
  - outputs.capacity_csv

Outputs:
  - outputs.hoster_counts_csv
"""

from __future__ import annotations

import os
import csv
import argparse
import logging
from typing import Dict, List, Tuple

try:
    import yaml
except ImportError:
    yaml = None

from hosterbenchmark.feeds.parsers import (
    FEED_REGISTRY,
    load_hosters,   # returns dict[str, list[str]]  hoster -> [cidrs...]
    _expand_files,   # glob/dir expansion helper
)
from hosterbenchmark.feeds.store import Store, Processor


logger = logging.getLogger("hosterbenchmark.step5")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(_handler)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _load_yaml(fp: str) -> dict:
    if yaml is None:
        raise RuntimeError("pyyaml is required to read YAML config files")
    with open(fp, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _load_capacity_map(capacity_csv: str) -> Dict[str, dict]:
    """
    Load step4 capacity so we can carry its columns into the final CSV even
    when no feeds are ingested.

    Returns: { hoster: row_dict }
    Keys typically include: Organization, domaincount, cidr_count, total_ips,
    avg_domains_per_ip, cidrs (JSON list string), etc.
    """
    out: Dict[str, dict] = {}
    if not capacity_csv or not os.path.isfile(capacity_csv):
        logger.info("Step 5: capacity CSV not found, continuing without carry-forward data")
        return out
    with open(capacity_csv, "r", encoding="utf-8", newline="") as fh:
        rdr = csv.DictReader(fh)
        for r in rdr:
            org = (r.get("Organization") or r.get("hoster") or "").strip()
            if not org:
                continue
            out[org] = r
    logger.info(f"Step 5: loaded {len(out)} capacity rows from {capacity_csv}")
    return out


# -------------------------------------------------------------------
# Core
# -------------------------------------------------------------------

def ingest_and_export(config_path: str) -> None:
    cfg = _load_yaml(config_path)

    # Required paths/outputs
    feeds_conf   = cfg.get("feeds_file")
    hosters_file = cfg.get("hosters_file")
    outputs      = cfg.get("outputs", {}) or {}
    paths        = cfg.get("paths", {}) or {}
    params       = cfg.get("params", {}) or {}

    lmdb_dir     = paths.get("lmdb_dir")
    output_csv   = outputs.get("hoster_counts_csv")
    commit_every = int(params.get("commit_every", 10000))
    lmdb_map_gb  = int(params.get("lmdb_map_gb", 64))

    if not hosters_file:
        raise ValueError("pipeline.yaml missing 'hosters_file'")
    if not lmdb_dir:
        raise ValueError("pipeline.yaml missing 'paths.lmdb_dir'")
    if not output_csv:
        raise ValueError("pipeline.yaml missing 'outputs.hoster_counts_csv'")
    if not feeds_conf:
        raise ValueError("pipeline.yaml missing 'feeds_file'")

    # Load hosters → [cidrs...]
    logger.info("Step 5: loading hosters...")
    hosters, _meta = load_hosters(hosters_file) if isinstance(load_hosters(hosters_file), tuple) else (load_hosters(hosters_file), {})
    all_hoster_names = list(hosters.keys())

    # Carry forward Step 4 capacity (optional but recommended)
    capacity_csv = outputs.get("capacity_csv", "")
    capacity_map = _load_capacity_map(capacity_csv)  # hoster -> row dict (from capacity)

    # Load feed list
    logger.info("Step 5: loading feeds...")
    with open(feeds_conf, "r", encoding="utf-8") as fh:
        feeds_yaml = yaml.safe_load(fh) or {}
    feeds_list = feeds_yaml.get("feeds", []) or []

    # Build list of (feed_name, path) we can actually run, and derive feed policy
    feed_specs: List[Tuple[str, str]] = []
    feeds_to_report: List[str] = []
    feed_policy: Dict[str, bool] = {}  # feed_name -> COUNT_DOMAINS (True = supports domain/IP split; False = IP-only)

    for item in feeds_list:
        name = item.get("name")
        path = item.get("path")
        if not name or not path:
            raise ValueError("Each feed in feeds.yaml needs 'name' and 'path'")
        if name not in FEED_REGISTRY:
            logger.warning(f"Feed '{name}' not in FEED_REGISTRY; skipping")
            continue

        parser_entry = FEED_REGISTRY[name]
        # Try to get COUNT_DOMAINS flag from class or instance
        count_domains = True
        try:
            # If it's a class or object with attribute
            if hasattr(parser_entry, "COUNT_DOMAINS"):
                count_domains = bool(getattr(parser_entry, "COUNT_DOMAINS"))
            else:
                # If it's a constructor, instantiate to inspect
                maybe_inst = parser_entry() if callable(parser_entry) else parser_entry
                if hasattr(maybe_inst, "COUNT_DOMAINS"):
                    count_domains = bool(getattr(maybe_inst, "COUNT_DOMAINS"))
        except Exception:
            pass

        feed_policy[name] = count_domains
        feed_specs.append((name, path))
        feeds_to_report.append(name)

    logger.info("Step 5: opening LMDB...")
    store = Store(lmdb_dir, map_size_gb=lmdb_map_gb)
    # Your Processor signature requires a feed_policy third arg
    proc = Processor(hosters, store, feed_policy)

    # Ingest feeds (if any)
    logger.info("Step 5: ingesting feeds...")
    n = 0
    txn = store.env.begin(write=True)
    for feed_name, path in feed_specs:
        parser_entry = FEED_REGISTRY[feed_name]
        # Resolve an instance with .iter_records(file_path)
        if hasattr(parser_entry, "iter_records"):
            parser = parser_entry  # already an instance-like object
        elif callable(parser_entry):
            parser = parser_entry()  # construct instance
        else:
            raise TypeError(f"FEED_REGISTRY['{feed_name}'] must be a class/instance with iter_records()")

        files = _expand_files(path)
        logger.info(f"[{feed_name}] Found {len(files)} files matching {path}")
        for f in files:
            logger.info(f"[{feed_name}] Processing {f}")
            try:
                for rec in parser.iter_records(f):
                    # rec should be a dict like: {"ip": "1.2.3.4", "source": feed_name, "domain": optional}
                    proc.ingest_record(rec, txn)
                    n += 1
                    if n % commit_every == 0:
                        txn.commit()
                        txn = store.env.begin(write=True)
            except Exception as e:
                logger.warning(f"Error in {f}: {e}")
    txn.commit()

    logger.info("Step 5: finalizing shared IPs...")
    proc.finalize_shared()

    # -------------------------------------------------------------------
    # Build final CSV (feeds + seen/shared + capacity carry-forward)
    # -------------------------------------------------------------------
    logger.info("Step 5: generating output CSV...")
    # Header: feed columns + store summary + capacity columns
    header = ["hoster"]
    for feed in feeds_to_report:
        # if COUNT_DOMAINS True, your Processor might track both domains and ips;
        # but to keep stable, we always at least output *_ips
        header.append(f"{feed}_ips")
    header += ["domaincount_seen", "ipcount_seen", "ipcount_shared", "domaincount_shared"]
    cap_cols = ["domaincount", "cidr_count", "total_ips", "avg_domains_per_ip", "cidrs"]
    header += cap_cols

    # Per-feed IP counts (grouped by (hoster, source))
    try:
        perfeed_ips = store.count_dups_grouped_hoster_source(store.db_hoster_src_ips)
    except Exception:
        perfeed_ips = {}

    # Overall counts
    try:
        domaincount_seen = store.count_dups(store.db_hoster_domains)
    except Exception:
        domaincount_seen = {}
    try:
        ipcount_seen = store.count_dups(store.db_hoster_ips)
    except Exception:
        ipcount_seen = {}
    try:
        domaincount_shared = store.count_dups(store.db_hoster_domains_sh)
    except Exception:
        domaincount_shared = {}

    ipcount_shared_map = getattr(proc, "ipcount_shared", {})

    # Names to output: union of capacity orgs and hoster list
    names_from_capacity = list(capacity_map.keys())
    names_from_hosters = all_hoster_names
    all_names = sorted(set(names_from_capacity) | set(names_from_hosters))

    with open(output_csv, "w", newline="", encoding="utf-8") as outfh:
        w = csv.writer(outfh)
        w.writerow(header)

        for hoster in all_names:
            row = [hoster]

            # feed columns
            for feed in feeds_to_report:
                row.append(str(perfeed_ips.get((hoster, feed), 0)))

            # store summary
            dcs = domaincount_seen.get(hoster, 0)
            ips = ipcount_seen.get(hoster, 0)
            ipsh = ipcount_shared_map.get(hoster, 0)
            dsh = domaincount_shared.get(hoster, 0)
            row.extend([str(dcs), str(ips), str(ipsh), str(dsh)])

            # capacity carry-forward
            cap = capacity_map.get(hoster, {})
            for c in cap_cols:
                row.append(str(cap.get(c, "")))

            w.writerow(row)

    logger.info(f"Wrote {output_csv}")
    store.close()


def main():
    ap = argparse.ArgumentParser(description="Step 5: Ingest IP-only feeds and count per hoster")
    ap.add_argument("--config", required=True, help="Path to pipeline.yaml")
    args = ap.parse_args()
    ingest_and_export(args.config)


if __name__ == "__main__":
    main()

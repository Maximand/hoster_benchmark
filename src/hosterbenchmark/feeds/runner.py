#!/usr/bin/env python3
"""
Step 5 — Ingest IP-only abuse feeds and (always) join capacity stats

This runner:
- Loads hosters (name -> list of CIDRs) for prefix->hoster mapping
- Loads capacity CSV (Organization, domaincount, cidr_count, total_ips, avg_domains_per_ip, cidrs)
- Ingests feeds (optional; zero is fine)
- Writes feeds.csv with both feed counts and capacity columns

If no feeds match (or the list is empty), you'll still get one row per hoster
with capacity fields filled in (when available).
"""

from __future__ import annotations

import os
import csv
import argparse
import logging
from typing import Dict, List, Tuple, Iterable

try:
    import yaml
except ImportError:
    yaml = None

from hosterbenchmark.feeds.parsers import FEED_REGISTRY, load_hosters, _expand_files
from hosterbenchmark.feeds.store import Store, Processor

logger = logging.getLogger("step5.ingest")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(_handler)


# ----------------------------
# Helpers
# ----------------------------

def _clean_name(s: str) -> str:
    """Normalize hoster/org names to improve joins across files."""
    if s is None:
        return ""
    s = str(s).strip()
    # Drop outer single/double quotes, including doubled quotes like ''foo''
    while (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
        s = s[1:-1].strip()
    # Also collapse doubled leading/trailing quotes
    if len(s) >= 4 and s[:2] == "''" and s[-2:] == "''":
        s = s[2:-2].strip()
    return s


def _load_yaml_config(cfg_path: str) -> dict:
    if yaml is None:
        raise RuntimeError("Install pyyaml or pass explicit CLI flags instead of --config")
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _load_capacity(capacity_csv: str) -> Dict[str, dict]:
    """
    Load Step 4 output:
      columns expected: Organization, domaincount, cidr_count, total_ips, avg_domains_per_ip, cidrs
    Returns: { normalized_name: row_dict }
    """
    if not capacity_csv or not os.path.exists(capacity_csv):
        logger.warning(f"Capacity CSV missing or not found: {capacity_csv!r}")
        return {}

    want = {"Organization", "domaincount", "cidr_count", "total_ips", "avg_domains_per_ip", "cidrs"}
    out: Dict[str, dict] = {}
    with open(capacity_csv, "r", encoding="utf-8", newline="") as fh:
        rdr = csv.DictReader(fh)
        cols = set(rdr.fieldnames or [])
        missing = want - cols
        if missing:
            logger.warning(f"Capacity CSV {capacity_csv} missing columns: {sorted(missing)}")

        for row in rdr:
            org = _clean_name(row.get("Organization", ""))
            if not org:
                continue
            out[org] = row
    logger.info(f"Step 5: loaded {len(out)} capacity rows from {capacity_csv}")
    return out


def _union_hoster_names(hosters: Dict[str, List[str]], capacity: Dict[str, dict]) -> List[str]:
    names = { _clean_name(n) for n in hosters.keys() }
    names.update(capacity.keys())
    return sorted(n for n in names if n)


# ----------------------------
# Main entry
# ----------------------------

def ingest_and_export(config_path: str):
    cfg = _load_yaml_config(config_path)

    feeds_conf   = cfg.get("feeds_file")
    hosters_file = cfg.get("hosters_file")
    outputs      = cfg.get("outputs") or {}
    paths        = cfg.get("paths") or {}
    params       = cfg.get("params") or {}

    output_csv   = outputs.get("hoster_counts_csv", "data/output/hoster_abuse_counts.csv")
    commit_every = int(params.get("commit_every", 10000))
    lmdb_map_gb  = int(params.get("lmdb_map_gb", 64))
    lmdb_dir     = paths.get("lmdb_dir", "data/work/lmdb")

    if not hosters_file:
        raise ValueError("pipeline.yaml must specify hosters_file")

    # Load hosters (CIDR map) and capacity (Step 4)
    logger.info("Step 5: loading hosters...")
    hosters = load_hosters(hosters_file)
    # Normalize keys
    hosters = {_clean_name(k): v for k, v in hosters.items()}

    capacity_csv = outputs.get("capacity_csv")
    capacity_map = _load_capacity(capacity_csv)

    # Union of names so we always output capacity-only rows too
    all_hoster_names = _union_hoster_names(hosters, capacity_map)

    logger.info("Step 5: loading feeds...")
    feeds_list: List[dict] = []
    if feeds_conf and os.path.exists(feeds_conf):
        with open(feeds_conf, "r", encoding="utf-8") as fh:
            feeds_yaml = yaml.safe_load(fh) or {}
        feeds_list = feeds_yaml.get("feeds", []) or []
    else:
        logger.info("No feeds.yaml found or specified; proceeding with zero feeds.")

    # Prepare store & processor for feed ingestion
    logger.info("Step 5: opening LMDB...")
    store = Store(lmdb_dir, map_size_gb=lmdb_map_gb)
    proc = Processor(hosters, store, feed_domain_policy={})

    # Build a lightweight feed registry: support any FEED_REGISTRY parser, or skip if none
    feed_specs: List[Tuple[str, str]] = []
    feeds_to_report: List[str] = []
    for item in feeds_list:
        name = item.get("name")
        path = item.get("path")
        if not name or not path:
            raise ValueError("Each feed in feeds.yaml needs 'name' and 'path'")
        if name not in FEED_REGISTRY:
            raise ValueError(f"Unknown feed: {name}")
        feed_specs.append((name, path))
        feeds_to_report.append(name)

    # Ingest (if any)
    logger.info("Step 5: ingesting feeds...")
    n = 0
    wtxn = store.env.begin(write=True)
    for feed_name, path in feed_specs:
        parser = FEED_REGISTRY[feed_name]()
        files = _expand_files(path)
        logger.info(f"[{feed_name}] Found {len(files)} files matching {path}")
        for f in files:
            logger.info(f"[{feed_name}] Processing {f}")
            try:
                for rec in parser.iter_records(f):
                    proc.ingest_record(rec, wtxn)
                    n += 1
                    if n % commit_every == 0:
                        wtxn.commit()
                        wtxn = store.env.begin(write=True)
            except Exception as e:
                logger.warning(f"Error in {f}: {e}")
    wtxn.commit()

    logger.info("Step 5: finalizing shared IPs...")
    proc.finalize_shared()

    # Collect feed counts from the LMDB store
    logger.info("Step 5: generating output CSV...")
    # For parsers in this runner, COUNT_DOMAINS is False, so only *_ips columns will show.
    # We still include the columns as <feed>_ips for every configured feed.
    header = ["hoster"]
    for feed in feeds_to_report:
        header.append(f"{feed}_ips")
    # Also include the summary fields from the store (even if zero)
    header += ["domaincount_seen", "ipcount_seen", "ipcount_shared", "domaincount_shared"]
    # And capacity fields (always appended)
    header += ["domaincount", "cidr_count", "total_ips", "avg_domains_per_ip", "cidrs"]

    # Summaries from the store
    ipcount_seen = store.count_dups(store.db_hoster_ips)
    domaincount_seen = store.count_dups(store.db_hoster_domains)
    domaincount_shared = store.count_dups(store.db_hoster_domains_sh)

    # Per-feed IP counts (grouped) — map (hoster, feed) -> count
    perfeed_ips = store.count_dups_grouped_hoster_source(store.db_hoster_src_ips)

    rows: List[List[str]] = []
    for hoster in all_hoster_names:
        row = [hoster]

        # Per-feed IP counts
        for feed in feeds_to_report:
            row.append(str(perfeed_ips.get((hoster, feed), 0)))

        # Store aggregate counts
        row.extend([
            str(domaincount_seen.get(hoster, 0)),
            str(ipcount_seen.get(hoster, 0)),
            str(proc.ipcount_shared.get(hoster, 0)),
            str(domaincount_shared.get(hoster, 0)),
        ])

        # Capacity (Step 4) — join by normalized name
        cap = capacity_map.get(hoster)
        if cap:
            row.extend([
                str(cap.get("domaincount", "")),
                str(cap.get("cidr_count", "")),
                str(cap.get("total_ips", "")),
                str(cap.get("avg_domains_per_ip", "")),
                str(cap.get("cidrs", "")),
            ])
        else:
            row.extend(["", "", "", "", ""])

        rows.append(row)

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as outfh:
        w = csv.writer(outfh)
        w.writerow(header)
        w.writerows(rows)

    logger.info(f"Wrote {output_csv}")
    store.close()


def main():
    ap = argparse.ArgumentParser(description="Step 5: Ingest IP-only feeds and join capacity stats")
    ap.add_argument("--config", required=True, help="pipeline.yaml")
    args = ap.parse_args()
    ingest_and_export(args.config)


if __name__ == "__main__":
    main()

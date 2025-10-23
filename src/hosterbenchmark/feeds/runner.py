#!/usr/bin/env python3
"""
Step 5 — Ingest IP-only abuse feeds and count hits per hoster,
then attach Step 4 capacity fields so the output already contains both.

Inputs (from pipeline.yaml):
  - feeds_file       (YAML listing feeds: [{name, path}, ...])
  - hosters_file     (or paths.cidr_map) — Organization → [CIDRs]
  - outputs.capacity_csv (produced by Step 4)

Output:
  - outputs.hoster_counts_csv (CSV) including feed counts + capacity columns
"""

import os
import csv
import argparse
import logging

from hosterbenchmark.feeds.parsers import FEED_REGISTRY, load_hosters
try:
    # prefer public name
    from hosterbenchmark.feeds.parsers import expand_files
except Exception:
    # backward-compat with older parsers.py
    from hosterbenchmark.feeds.parsers import _expand_files as expand_files

from hosterbenchmark.feeds.store import Store, Processor

try:
    import yaml
except ImportError:
    yaml = None

import pandas as pd

logger = logging.getLogger("step5.ingest")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(_handler)


def _load_yaml_config(cfg_path: str) -> dict:
    if yaml is None:
        raise RuntimeError("Install pyyaml or pass fully-specified args")
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _normalize_org(s: str) -> str:
    """Normalize org/hoster strings for robust joins (strip outer quotes, spaces)."""
    if s is None:
        return ""
    s = str(s).strip()
    # remove doubled outer quotes
    if s.startswith("''") and s.endswith("''") and len(s) >= 4:
        s = s[2:-2]
    # remove single outer quotes
    elif (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
        s = s[1:-1]
    # final clean
    s = s.strip().strip("'").strip('"').strip()
    # collapse doubled internal apostrophes to single
    s = s.replace("''", "'")
    return s


def _unpack_load_hosters(result):
    """
    load_hosters() may return:
      - dict: {org: [cidr,...]}
      - (dict, meta): (prefix_map, metadata)
    Normalize to (prefix_map, meta_dict).
    """
    if isinstance(result, tuple) and len(result) == 2:
        return result[0] or {}, result[1] or {}
    return result or {}, {}


def _load_capacity(capacity_csv: str):
    """Load Step 4 capacity CSV and build a normalized map: org_norm -> {...fields}."""
    if not capacity_csv or not os.path.exists(capacity_csv):
        logger.warning(f"Capacity CSV not found: {capacity_csv} (Step 5 will proceed without Step 4 fields).")
        return {}

    df = pd.read_csv(capacity_csv)
    # tolerate different casings or missing columns
    org_col = "Organization" if "Organization" in df.columns else ("org" if "org" in df.columns else None)
    if org_col is None:
        logger.warning(f"Capacity CSV {capacity_csv} missing Organization/org column; skipping attach.")
        return {}

    # Ensure expected fields exist (fill defaults if absent)
    for col, default in [
        ("domaincount", 0),
        ("cidr_count", 0),
        ("total_ips", 0),
        ("avg_domains_per_ip", 0.0),
        ("cidrs", ""),
    ]:
        if col not in df.columns:
            df[col] = default

    df["_org_norm"] = df[org_col].apply(_normalize_org)
    df = df[["_org_norm", "domaincount", "cidr_count", "total_ips", "avg_domains_per_ip", "cidrs"]].copy()

    cap_map = {}
    for _, row in df.iterrows():
        cap_map[row["_org_norm"]] = {
            "domaincount": int(row["domaincount"]) if pd.notna(row["domaincount"]) else 0,
            "cidr_count": int(row["cidr_count"]) if pd.notna(row["cidr_count"]) else 0,
            "total_ips": int(row["total_ips"]) if pd.notna(row["total_ips"]) else 0,
            "avg_domains_per_ip": float(row["avg_domains_per_ip"]) if pd.notna(row["avg_domains_per_ip"]) else 0.0,
            "cidrs": row["cidrs"] if pd.notna(row["cidrs"]) else "",
        }
    return cap_map


def ingest_and_export(config_path: str):
    cfg = _load_yaml_config(config_path)

    paths   = cfg.get("paths", {}) or {}
    outputs = cfg.get("outputs", {}) or {}
    params  = cfg.get("params", {}) or {}

    feeds_conf   = cfg.get("feeds_file")                       # e.g. config/feeds.yaml
    hosters_file = cfg.get("hosters_file") or paths.get("cidr_map")

    lmdb_dir     = paths.get("lmdb_dir", "data/work/lmdb")
    output_csv   = outputs.get("hoster_counts_csv", "data/output/hoster_abuse_counts.csv")
    capacity_csv = outputs.get("capacity_csv")  # Step 4 output

    commit_every = int(params.get("commit_every", 10000))
    lmdb_map_gb  = int(params.get("lmdb_map_gb", 64))

    if not hosters_file:
        raise ValueError("pipeline.yaml is missing 'hosters_file' (or paths.cidr_map).")
    if not feeds_conf:
        raise ValueError("pipeline.yaml is missing 'feeds_file' (path to feeds.yaml).")

    # Load hosters
    logger.info("Step 5: loading hosters...")
    prefix_map_raw = load_hosters(hosters_file)
    hosters, hoster_meta = _unpack_load_hosters(prefix_map_raw)
    if not hosters:
        raise ValueError(f"No hosters parsed from {hosters_file}")
    all_hoster_names = sorted(hosters.keys())

    # Load feeds list
    logger.info("Step 5: loading feeds...")
    with open(feeds_conf, "r", encoding="utf-8") as fh:
        feeds_yaml = yaml.safe_load(fh) or {}
    feeds_list = feeds_yaml.get("feeds", [])
    if not feeds_list:
        logger.warning(f"No feeds defined in {feeds_conf}")

    parser_objs = {}
    feeds_to_report = []
    feed_specs = []
    for item in feeds_list:
        name = item.get("name")
        path = item.get("path")
        if not name or not path:
            raise ValueError("Each feed in feeds.yaml needs 'name' and 'path'")
        if name not in FEED_REGISTRY:
            raise ValueError(f"Unknown feed: {name}. Add a parser in feeds/parsers.py")
        if name not in parser_objs:
            parser_objs[name] = FEED_REGISTRY[name]()  # instantiate
        feeds_to_report.append(name)
        feed_specs.append((name, path))

    # Per-feed domain policy
    feed_domain_policy = {
        name: bool(getattr(parser_objs[name], "COUNT_DOMAINS", True))
        for name in parser_objs
    }

    # Load Step 4 capacity map (normalized)
    cap_map = _load_capacity(capacity_csv)

    # LMDB + Processor
    logger.info("Step 5: opening LMDB...")
    os.makedirs(lmdb_dir, exist_ok=True)
    store = Store(lmdb_dir, map_size_gb=lmdb_map_gb)
    proc = Processor(hosters, store, feed_domain_policy)

    # Ingest feeds
    logger.info("Step 5: ingesting feeds...")
    txn = store.env.begin(write=True)
    n = 0
    for name, path in feed_specs:
        parser = parser_objs[name]
        files = expand_files(path)
        logger.info(f"[{name}] Found {len(files)} files matching {path}")
        for f in files:
            logger.info(f"[{name}] Processing {f}")
            seen_in_file = 0
            try:
                for rec in parser.iter_records(f):
                    seen_in_file += 1
                    proc.ingest_record(rec, txn)
                    n += 1
                    if n % commit_every == 0:
                        txn.commit()
                        txn = store.env.begin(write=True)
            except Exception as e:
                logger.warning(f"Error in {f}: {e}")
            logger.info(f"[{name}] yielded {seen_in_file} records from {os.path.basename(f)}")
    txn.commit()

    # Finalize shared IPs
    logger.info("Step 5: finalizing shared IPs...")
    proc.finalize_shared()

    # Compose output header: feed columns + store summary + capacity fields
    logger.info("Step 5: generating output CSV...")
    header = ["hoster"]
    for feed in feeds_to_report:
        if feed_domain_policy.get(feed, True):
            header += [f"{feed}_domains", f"{feed}_ips"]
        else:
            header += [f"{feed}_ips"]
    header += ["domaincount_seen", "ipcount_seen", "ipcount_shared", "domaincount_shared"]
    # Step 4 fields appended
    header += ["domaincount", "cidr_count", "total_ips", "avg_domains_per_ip", "cidrs"]

    # Base rows from store
    base_rows = proc.results(all_hoster_names, feeds_to_report, feed_domain_policy)

    # Attach capacity by normalized name
    out_rows = []
    for row in base_rows:
        hoster_name = row[0]
        org_norm = _normalize_org(hoster_name)
        cap = cap_map.get(org_norm, None)
        if cap:
            row_ext = row + [
                cap["domaincount"],
                cap["cidr_count"],
                cap["total_ips"],
                cap["avg_domains_per_ip"],
                cap["cidrs"],
            ]
        else:
            row_ext = row + [0, 0, 0, 0.0, ""]
        out_rows.append(row_ext)

    # Write CSV
    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as outfh:
        w = csv.writer(outfh)
        w.writerow(header)
        w.writerows(out_rows)

    logger.info(f"Wrote {output_csv}")
    store.close()


def main():
    ap = argparse.ArgumentParser(description="Step 5: Ingest IP-only feeds and count per hoster (with Step 4 capacity attached)")
    ap.add_argument("--config", required=True, help="pipeline.yaml")
    args = ap.parse_args()
    ingest_and_export(args.config)


if __name__ == "__main__":
    main()

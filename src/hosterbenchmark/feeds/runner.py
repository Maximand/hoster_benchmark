#!/usr/bin/env python3
"""
Step 5 — Ingest IP-only abuse feeds and count hits per hoster.

Inputs:
  - pipeline.yaml (this function reads it)
  - feeds.yaml    (referenced by pipeline.yaml as feeds_file)
  - hosters file  (CSV/pipe/MaxMind-like; referenced by pipeline.yaml as hosters_file)
Outputs:
  - outputs.hoster_counts_csv (pipe CSV)
"""

import os
import csv
import glob
import argparse
import logging

from hosterbenchmark.feeds.parsers import FEED_REGISTRY, load_hosters, expand_files
from hosterbenchmark.feeds.store import Store, Processor

try:
    import yaml
except ImportError:
    yaml = None

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


def ingest_and_export(config_path: str):
    cfg = _load_yaml_config(config_path)

    # --- pull paths/outputs/params from pipeline.yaml ---
    paths   = cfg.get("paths", {}) or {}
    outputs = cfg.get("outputs", {}) or {}
    params  = cfg.get("params", {}) or {}

    feeds_conf   = cfg.get("feeds_file")                 # e.g. config/feeds.yaml
    hosters_file = cfg.get("hosters_file")               # <-- IMPORTANT: define this
    lmdb_dir     = paths.get("lmdb_dir", "data/work/lmdb")
    output_csv   = outputs.get("hoster_counts_csv", "data/output/hoster_abuse_counts.csv")

    commit_every = int(params.get("commit_every", 10000))
    lmdb_map_gb  = int(params.get("lmdb_map_gb", 64))

    if not hosters_file:
        raise ValueError("pipeline.yaml is missing 'hosters_file'")
    if not feeds_conf:
        raise ValueError("pipeline.yaml is missing 'feeds_file' (path to feeds.yaml)")

    logger.info("Step 5: loading hosters...")
    # load_hosters returns (prefix_map, metadata) where prefix_map is {org: [cidr,...]}
    prefix_map, hoster_meta = load_hosters(hosters_file)
    hosters = prefix_map
    all_hoster_names = sorted(hosters.keys())

    logger.info("Step 5: loading feeds...")
    with open(feeds_conf, "r", encoding="utf-8") as fh:
        feeds_yaml = yaml.safe_load(fh) or {}
    feeds_list = feeds_yaml.get("feeds", [])

    # Build parser objects per feed
    parser_objs = {}
    feed_specs = []
    feeds_to_report = []

    for item in feeds_list:
        name = item.get("name")
        path = item.get("path")
        if not name or not path:
            raise ValueError("Each feed in feeds.yaml needs 'name' and 'path'")
        if name not in FEED_REGISTRY:
            raise ValueError(f"Unknown feed: {name}. Add a parser in feeds/parsers.py")
        if name not in parser_objs:
            parser_objs[name] = FEED_REGISTRY[name]()  # instantiate the parser
        feeds_to_report.append(name)
        feed_specs.append((name, path))

    # Determine which feeds count domains (most of yours are IP-only → False)
    feed_domain_policy = {name: bool(getattr(parser_objs[name], "COUNT_DOMAINS", True))
                          for name in parser_objs}

    # Open LMDB + Processor
    logger.info("Step 5: opening LMDB...")
    os.makedirs(lmdb_dir, exist_ok=True)
    store = Store(lmdb_dir, map_size_gb=lmdb_map_gb)
    proc = Processor(hosters, store, feed_domain_policy)

    # Ingest
    logger.info("Step 5: ingesting feeds...")
    txn = store.env.begin(write=True)
    n = 0

    for name, path in feed_specs:
        parser = parser_objs[name]
        files = expand_files(path)
        logger.info(f"[{name}] Found {len(files)} files matching {path}")
        for f in files:
            logger.info(f"[{name}] Processing {f}")
            try:
                for rec in parser.iter_records(f):
                    proc.ingest_record(rec, txn)
                    n += 1
                    if n % commit_every == 0:
                        txn.commit()
                        txn = store.env.begin(write=True)
            except Exception as e:
                logger.warning(f"Error in {f}: {e}")

    txn.commit()

    # Derive shared IPs (relevant only if any feed counted domains)
    logger.info("Step 5: finalizing shared IPs...")
    proc.finalize_shared()

    # Prepare header
    logger.info("Step 5: generating output CSV...")
    header = ["hoster"]
    for feed in feeds_to_report:
        if feed_domain_policy.get(feed, True):
            header += [f"{feed}_domains", f"{feed}_ips"]
        else:
            header += [f"{feed}_ips"]
    header += ["domaincount_seen", "ipcount_seen", "ipcount_shared", "domaincount_shared"]

    rows = proc.results(all_hoster_names, feeds_to_report, feed_domain_policy)

    os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as outfh:
        w = csv.writer(outfh)
        w.writerow(header)
        w.writerows(rows)

    logger.info(f"Wrote {output_csv}")
    store.close()


def main():
    ap = argparse.ArgumentParser(description="Step 5: Ingest IP-only feeds and count per hoster")
    ap.add_argument("--config", required=True, help="pipeline.yaml")
    args = ap.parse_args()
    ingest_and_export(args.config)


if __name__ == "__main__":
    main()

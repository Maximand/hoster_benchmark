#!/usr/bin/env python3
"""
Step 5 — Ingest IP-only abuse feeds and count hits per hoster

Uses:
- hosterbenchmark.feeds.parsers (feed registry with line → [IP] functions)
- hosterbenchmark.feeds.store   (LMDB store + Processor logic)

Inputs:
  - feeds.yaml
  - hosters.csv/yaml/pipe
  - feed files (glob paths)

Output:
  - hoster_abuse_counts.csv
"""

import os
import csv
import argparse
import logging

from hosterbenchmark.feeds.parsers import FEED_REGISTRY, load_hosters, _expand_files
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
        raise RuntimeError("Install pyyaml or use CLI flags instead of --config")
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}

def ingest_and_export(config_path: str):
    cfg = _load_yaml_config(config_path)

    feeds_conf = cfg.get("feeds_file")
    hosters, hoster_meta = load_hosters(cfg["paths"]["cidr_map"], return_meta=True)
    lmdb_dir = cfg["paths"]["lmdb_dir"]
    output_csv = cfg["outputs"]["hoster_counts_csv"]

    params = cfg.get("params", {})
    commit_every = int(params.get("commit_every", 10000))
    lmdb_map_gb = int(params.get("lmdb_map_gb", 64))

    logger.info("Step 5: loading hosters...")
    hosters = load_hosters(hosters_file)
    all_hoster_names = list(hosters.keys())

    logger.info("Step 5: loading feeds...")
    with open(feeds_conf, "r", encoding="utf-8") as fh:
        feeds_yaml = yaml.safe_load(fh) or {}
    feeds_list = feeds_yaml.get("feeds", [])

    feed_parsers = {}
    feed_specs = []
    feeds_to_report = []
    for item in feeds_list:
        name = item.get("name")
        path = item.get("path")
        if not name or not path:
            raise ValueError("Each feed in feeds.yaml needs 'name' and 'path'")
        if name not in FEED_REGISTRY:
            raise ValueError(f"Unknown feed: {name}")
        feed_parsers[name] = FEED_REGISTRY[name]  # function: line → [ips]
        feed_specs.append((name, path))
        feeds_to_report.append(name)

    feed_domain_policy = {
        name: getattr(feed_parsers[name], "COUNT_DOMAINS", True)
        for name in feed_parsers
    }

    logger.info("Step 5: opening LMDB...")
    store = Store(lmdb_dir, map_size_gb=lmdb_map_gb)
    proc = Processor(hosters, store, feed_domain_policy)

    logger.info("Step 5: ingesting feeds...")
    txn = store.env.begin(write=True)
    n = 0

    for name, path in feed_specs:
        parser = feed_parsers[name]
        files = _expand_files(path)
        logger.info(f"[{name}] Found {len(files)} files matching {path}")
        for f in files:
            logger.info(f"[{name}] Processing {f}")
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    try:
                        ips = parser(line)
                        for ip in ips:
                            proc.ingest_record((None, ip), txn)
                            n += 1
                            if n % commit_every == 0:
                                txn.commit()
                                txn = store.env.begin(write=True)
                    except Exception as e:
                        logger.warning(f"Error in {f}: {e}")
    txn.commit()

    logger.info("Step 5: finalizing shared IPs...")
    proc.finalize_shared()

    # Generate output CSV
    logger.info("Step 5: generating output CSV...")
    header = ["hoster"]
    for feed in feeds_to_report:
        if feed_domain_policy[feed]:
            header += [f"{feed}_domains", f"{feed}_ips"]
        else:
            header += [f"{feed}_ips"]
    header += ["domaincount_seen", "ipcount_seen", "ipcount_shared", "domaincount_shared"]

    rows = proc.results(all_hoster_names, feeds_to_report, feed_domain_policy)

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

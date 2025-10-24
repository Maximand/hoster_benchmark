#!/usr/bin/env python3
"""
Step 5 — Ingest IP-only abuse feeds and count hits per hoster.

Inputs (from pipeline.yaml):
  - feeds_file: path to YAML with a 'feeds:' list of {name, path}
  - hosters_file: path to hoster/CIDR mapping (MaxMind-derived CSV/pipe)
  - paths.lmdb_dir: directory for LMDB environment
  - outputs.capacity_csv: Step 4 output with capacity columns

Outputs:
  - outputs.hoster_counts_csv
"""

from __future__ import annotations

import os
import re
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
    load_hosters,     # returns dict[str, list[str]]  hoster -> [cidrs...]
    _expand_files,    # glob/dir expansion helper
)
from hosterbenchmark.feeds.store import Store, Processor


logger = logging.getLogger("hosterbenchmark.step5")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(_handler)


# ---------------------------- utils ----------------------------

_STRIP_QUOTES_RE = re.compile(r"""^\s*['"]?(.*?)['"]?\s*$""")

def normalize_name(s: str) -> str:
    if s is None:
        return ""
    # strip outer quotes/apostrophes and whitespace
    m = _STRIP_QUOTES_RE.match(str(s))
    return (m.group(1) if m else str(s)).strip()


def _load_yaml(fp: str) -> dict:
    if yaml is None:
        raise RuntimeError("pyyaml is required to read YAML config files")
    with open(fp, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _load_capacity_map(capacity_csv: str) -> Dict[str, dict]:
    """
    Load step4 capacity so we can carry its columns into the final CSV
    even when no feeds are ingested.

    Returns: { normalized_hoster: row_dict }
    Keys include: Organization, domaincount, cidr_count, total_ips,
    avg_domains_per_ip, cidrs, etc.
    """
    out: Dict[str, dict] = {}
    if not capacity_csv or not os.path.isfile(capacity_csv):
        logger.info("Step 5: capacity CSV not found, continuing without carry-forward data")
        return out
    with open(capacity_csv, "r", encoding="utf-8", newline="") as fh:
        rdr = csv.DictReader(fh)
        for r in rdr:
            org_raw = r.get("Organization") or r.get("hoster") or ""
            org = normalize_name(org_raw)
            if not org:
                continue
            out[org] = r
    logger.info(f"Step 5: loaded {len(out)} capacity rows from {capacity_csv}")
    return out


# ---------------------------- core ----------------------------

def ingest_and_export(config_path: str) -> None:
    cfg = _load_yaml(config_path)

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

    # Load hosters → [cidrs...] and normalize their names
    logger.info("Step 5: loading hosters...")
    loaded = load_hosters(hosters_file)
    if isinstance(loaded, tuple):
        hosters_raw, _meta = loaded
    else:
        hosters_raw, _meta = loaded, {}

    hosters: Dict[str, List[str]] = {
        normalize_name(k): v for k, v in hosters_raw.items()
    }
    all_hoster_names = list(hosters.keys())

    # Carry forward Step 4 capacity (preferred universe for output rows)
    capacity_csv = outputs.get("capacity_csv", "")
    capacity_map = _load_capacity_map(capacity_csv)  # normalized names

    # Optional: build domain->org map from Step 2 triplets (for domain-only feeds)
    # (kept for future use; safe no-op if not used by your parsers)
    domain_map: Dict[str, str] = {}
    step2_dir = paths.get("step2_out_dir")
    if step2_dir and os.path.isdir(step2_dir):
        built = 0
        try:
            for name in os.listdir(step2_dir):
                if not name.startswith("step3_enriched_") or not name.endswith(".txt"):
                    continue
                with open(os.path.join(step2_dir, name), "r", encoding="utf-8") as fh:
                    for line in fh:
                        # format: "sld | ip | org"
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) < 3:
                            continue
                        sld = parts[0]
                        org = normalize_name(parts[2])
                        if not sld or not org:
                            continue
                        if sld not in domain_map:
                            domain_map[sld] = org
                            built += 1
            if built:
                logger.info(f"Step 5: built {built} sld->org mappings from Step 2 outputs")
        except Exception as e:
            logger.warning(f"Step 5: failed building domain map from Step 2: {e}")

    # Load feeds list
    logger.info("Step 5: loading feeds...")
    with open(feeds_conf, "r", encoding="utf-8") as fh:
        feeds_yaml = yaml.safe_load(fh) or {}
    feeds_list = feeds_yaml.get("feeds", []) or []

    feed_specs: List[Tuple[str, str]] = []
    feeds_to_report: List[str] = []
    for item in feeds_list:
        name = item.get("name")
        path = item.get("path")
        if not name or not path:
            raise ValueError("Each feed in feeds.yaml needs 'name' and 'path'")
        if name not in FEED_REGISTRY:
            logger.warning(f"Feed '{name}' not in FEED_REGISTRY; skipping")
            continue
        feed_specs.append((name, path))
        feeds_to_report.append(name)

    # Prepare store & processor
    logger.info("Step 5: opening LMDB...")
    store = Store(lmdb_dir, map_size_gb=lmdb_map_gb)
    # Processor(hosters, store, feed_policy) in your current code; if your Processor
    # takes only (hosters, store), this call still works by ignoring domain_map.
    # We pass an empty feed policy here (all IP-only feeds), but you can extend later.
    try:
        proc = Processor(hosters, store, {})
    except TypeError:
        # fallback for older signature Processor(hosters, store)
        proc = Processor(hosters, store)

    # Ingest feeds
    logger.info("Step 5: ingesting feeds...")
    n = 0
    txn = store.env.begin(write=True)
    for feed_name, path in feed_specs:
        parser_entry = FEED_REGISTRY[feed_name]
        parser = parser_entry() if callable(parser_entry) else parser_entry
        files = _expand_files(path)
        logger.info(f"[{feed_name}] Found {len(files)} files matching {path}")
        for f in files:
            logger.info(f"[{feed_name}] Processing {f}")
            try:
                for rec in parser.iter_records(f):
                    # normalize hoster via CIDR or domain mapping happens inside Processor/Store
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

    # ----------------- build final CSV (always include capacity) -----------------

    logger.info("Step 5: generating output CSV...")

    header = ["hoster"]
    for feed in feeds_to_report:
        header.append(f"{feed}_ips")
    header += ["domaincount_seen", "ipcount_seen", "ipcount_shared", "domaincount_shared"]
    cap_cols = ["domaincount", "cidr_count", "total_ips", "avg_domains_per_ip", "cidrs"]
    header += cap_cols

    # Per-feed IP counts grouped by (hoster, feed)
    try:
        perfeed_ips = store.count_dups_grouped_hoster_source(store.db_hoster_src_ips)
    except Exception:
        perfeed_ips = {}

    # Overall seen/shared
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

    # Prefer the capacity universe for output rows (ensures totals even with zero feeds)
    if capacity_map:
        output_names = sorted(capacity_map.keys())
    else:
        # fallback: use hosters if capacity missing
        output_names = sorted(set(all_hoster_names))

    with open(output_csv, "w", newline="", encoding="utf-8") as outfh:
        w = csv.writer(outfh)
        w.writerow(header)

        for hoster in output_names:
            row = [hoster]

            # feed columns (zeros if none)
            for feed in feeds_to_report:
                row.append(str(perfeed_ips.get((hoster, feed), 0)))

            # store summary (zeros if none)
            dcs = domaincount_seen.get(hoster, 0)
            ips = ipcount_seen.get(hoster, 0)
            ipsh = ipcount_shared_map.get(hoster, 0)
            dsh = domaincount_shared.get(hoster, 0)
            row.extend([str(dcs), str(ips), str(ipsh), str(dsh)])

            # capacity carry-forward (always filled for capacity universe)
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

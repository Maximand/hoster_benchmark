#!/usr/bin/env python3
"""
Step 5 — Ingest IP-only/domain-only abuse feeds and count hits per hoster.

Inputs (from pipeline.yaml):
  - feeds_file: path to YAML with a 'feeds:' list of {name, path}
  - hosters_file: path to hoster/CIDR mapping (MaxMind-derived CSV/pipe)
  - paths.lmdb_dir: directory for LMDB environment
  - paths.step2_out_dir: directory with Step-2 triplets (sld | ip | Organization)
  - (optional) paths.domain_map_csv: pipe-delimited CSV with: sld|Organization

Also carries forward Step 4 capacity metrics by reading:
  - outputs.capacity_csv

Outputs:
  - outputs.hoster_counts_csv
"""

from __future__ import annotations

import os
import csv
import glob
import argparse
import logging
from typing import Dict, List, Tuple, Optional
from collections import defaultdict, Counter

try:
    import yaml
except ImportError:
    yaml = None

# Parsers & store/processor primitives exposed by your project
from hosterbenchmark.feeds.parsers import (
    FEED_REGISTRY,     # dict: feed_name -> parser class/instance
    load_hosters,      # returns dict[str, list[str]] OR (dict[str, list[str]], meta)
)
from hosterbenchmark.feeds.store import Store, Processor

logger = logging.getLogger("hosterbenchmark.step5")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(_handler)


# -------------------------------------------------------------------
# Small helpers
# -------------------------------------------------------------------

def _load_yaml(fp: str) -> dict:
    if yaml is None:
        raise RuntimeError("pyyaml is required to read YAML config files")
    with open(fp, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _expand_files(path: str) -> List[str]:
    """Accept a file, dir, or glob; return a list of files."""
    if not path:
        return []
    # glob?
    if any(ch in path for ch in ["*", "?", "["]):
        return [p for p in glob.glob(path) if os.path.isfile(p)]
    # dir?
    if os.path.isdir(path):
        out = []
        for root, _dirs, files in os.walk(path):
            out.extend([os.path.join(root, f) for f in files])
        return out
    # file
    return [path] if os.path.isfile(path) else []


def _load_capacity_map(capacity_csv: str) -> Dict[str, dict]:
    """
    Load Step 4 capacity so we can carry its columns into the final CSV even
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


def _load_domain_map(csv_path: str) -> Dict[str, str]:
    """
    Optional explicit domain map file (pipe-delimited):
      sld|Organization
    Returns dict: sld_lower -> Organization
    """
    m: Dict[str, str] = {}
    if not csv_path or not os.path.isfile(csv_path):
        return m
    with open(csv_path, "r", encoding="utf-8", newline="") as fh:
        rdr = csv.DictReader(fh, delimiter="|")
        required = {"sld", "Organization"}
        if not set(rdr.fieldnames or ()) >= required:
            raise ValueError(
                f"{csv_path} must have pipe-delimited columns: sld|Organization"
            )
        for r in rdr:
            sld = (r.get("sld") or "").strip().lower()
            org = (r.get("Organization") or "").strip()
            if sld and org:
                m[sld] = org
    logger.info(f"Step 5: loaded {len(m)} sld->org mappings from {csv_path}")
    return m


def _build_sld_org_from_step2(step2_out_dir: Optional[str]) -> Dict[str, str]:
    """
    Build sld->Organization map from Step 2 triplet files:
      <sld> | <ip> | <Organization>

    We look for:  step3_enriched_*.txt  inside step2_out_dir
    If multiple orgs appear for the same sld, we keep the most frequent one.
    """
    m: Dict[str, str] = {}
    if not step2_out_dir:
        return m

    pattern = os.path.join(step2_out_dir, "step3_enriched_*.txt")
    files = sorted(glob.glob(pattern))
    if not files:
        logger.info(f"Step 5: no Step 2 files matching {pattern}; domain inference from Step 2 disabled.")
        return m

    counts: Dict[str, Counter] = defaultdict(Counter)

    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                for line in fh:
                    # "<sld> | <ip> | <Organization>"
                    parts = [p.strip() for p in line.rstrip("\n").split("|")]
                    if len(parts) < 3:
                        continue
                    sld, _ip, org = parts[0], parts[1], parts[2]
                    if not sld or not org:
                        continue
                    counts[sld.lower()][org] += 1
        except Exception as e:
            logger.warning(f"Step 5: failed reading {fp}: {e}")

    for sld, counter in counts.items():
        org, _ = counter.most_common(1)[0]
        m[sld] = org

    logger.info(f"Step 5: built {len(m)} sld->org mappings from Step 2 outputs")
    return m


def _sld(domain: str) -> str:
    """
    Heuristic SLD extraction: take last two labels.
    (Good enough for feeds attribution since Step-2 triplets already use this form.)
    """
    if not domain:
        return ""
    d = domain.strip(".").lower()
    parts = [p for p in d.split(".") if p]
    if len(parts) < 2:
        return d
    return ".".join(parts[-2:])


# -------------------------------------------------------------------
# Core
# -------------------------------------------------------------------

def ingest_and_export(config_path: str) -> None:
    cfg = _load_yaml(config_path)

    feeds_conf   = cfg.get("feeds_file")
    hosters_file = cfg.get("hosters_file")
    outputs      = cfg.get("outputs", {}) or {}
    paths        = cfg.get("paths", {}) or {}
    params       = cfg.get("params", {}) or {}

    lmdb_dir     = paths.get("lmdb_dir")
    output_csv   = outputs.get("hoster_counts_csv")
    capacity_csv = outputs.get("capacity_csv", "")
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
    loaded = load_hosters(hosters_file)
    if isinstance(loaded, tuple):
        hosters, _meta = loaded
    else:
        hosters, _meta = loaded, {}
    all_hoster_names = list(hosters.keys())

    # Carry forward Step 4 capacity
    capacity_map = _load_capacity_map(capacity_csv)

    # Domain attribution map: explicit CSV beats implicit-from-step2
    domain_map_csv = paths.get("domain_map_csv", "")
    if domain_map_csv and os.path.isfile(domain_map_csv):
        domain_map = _load_domain_map(domain_map_csv)
    else:
        domain_map = _build_sld_org_from_step2(paths.get("step2_out_dir"))

    # Prepare store/processor
    logger.info("Step 5: opening LMDB...")
    store = Store(lmdb_dir, map_size_gb=lmdb_map_gb)

    # FEED_POLICY: detect whether a feed counts domains distinctly or is IP-only
    feed_policy: Dict[str, bool] = {}

    # Parse feeds.yaml
    logger.info("Step 5: loading feeds...")
    with open(feeds_conf, "r", encoding="utf-8") as fh:
        feeds_yaml = yaml.safe_load(fh) or {}
    feeds_list = feeds_yaml.get("feeds", []) or []

    # Build concrete feed list
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

        parser_entry = FEED_REGISTRY[name]
        # Discover COUNT_DOMAINS flag (True means domains+IPs available)
        count_domains = True
        try:
            if hasattr(parser_entry, "COUNT_DOMAINS"):
                count_domains = bool(getattr(parser_entry, "COUNT_DOMAINS"))
            else:
                maybe_inst = parser_entry() if callable(parser_entry) else parser_entry
                if hasattr(maybe_inst, "COUNT_DOMAINS"):
                    count_domains = bool(getattr(maybe_inst, "COUNT_DOMAINS"))
        except Exception:
            pass

        feed_policy[name] = count_domains
        feed_specs.append((name, path))
        feeds_to_report.append(name)

    # Processor(hosters, store, feed_policy) — this matches your current signature
    proc = Processor(hosters, store, feed_policy)

    # Ingest feeds (if any)
    logger.info("Step 5: ingesting feeds...")
    n = 0
    txn = store.env.begin(write=True)
    for feed_name, path in feed_specs:
        parser_entry = FEED_REGISTRY[feed_name]
        # Resolve an instance with .iter_records(file_path)
        if hasattr(parser_entry, "iter_records"):
            parser = parser_entry  # instance-like
        elif callable(parser_entry):
            parser = parser_entry()  # construct
        else:
            raise TypeError(f"FEED_REGISTRY['{feed_name}'] must provide iter_records(file)")

        files = _expand_files(path)
        logger.info(f"[{feed_name}] Found {len(files)} files matching {path}")
        for f in files:
            logger.info(f"[{feed_name}] Processing {f}")
            try:
                for rec in parser.iter_records(f):
                    # Expecting dicts like: {"ip": "1.2.3.4"} or {"domain": "example.com"} or both.
                    ip = (rec.get("ip") or "").strip()
                    dom = (rec.get("domain") or "").strip()
                    src = feed_name

                    if dom and not ip and domain_map:
                        s = _sld(dom)
                        mapped_org = domain_map.get(s)
                        if mapped_org:
                            # force attribution via _org for domain-only hits
                            proc.ingest_record({"domain": dom, "source": src, "_org": mapped_org}, txn)
                        # else: un-attributable domain-only; skip
                    else:
                        # normal path; Processor will attribute IPs via CIDRs and domains via its own logic
                        proc.ingest_record({"ip": ip, "domain": dom, "source": src}, txn)

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
    header = ["hoster"]
    for feed in feeds_to_report:
        header.append(f"{feed}_ips")
    header += ["domaincount_seen", "ipcount_seen", "ipcount_shared", "domaincount_shared"]
    cap_cols = ["domaincount", "cidr_count", "total_ips", "avg_domains_per_ip", "cidrs"]
    header += cap_cols

    # Per-feed IP counts (grouped by (hoster, source))
    try:
        perfeed_ips = store.count_dups_grouped_hoster_source(store.db_hoster_src_ips)
    except Exception:
        perfeed_ips = {}

    # Overall counts accumulated in the store
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

    # Write CSV
    with open(output_csv, "w", newline="", encoding="utf-8") as outfh:
        w = csv.writer(outfh)
        w.writerow(header)

        for hoster in all_names:
            row = [hoster]

            # per-feed columns
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
    ap = argparse.ArgumentParser(description="Step 5: Ingest IP/domain feeds and count per hoster")
    ap.add_argument("--config", required=True, help="Path to pipeline.yaml")
    args = ap.parse_args()
    ingest_and_export(args.config)


if __name__ == "__main__":
    main()

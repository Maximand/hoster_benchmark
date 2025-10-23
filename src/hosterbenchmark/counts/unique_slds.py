#!/usr/bin/env python3
"""
Step 3 — Count unique registrable domains (SLDs) per org
Input:  step3_enriched_*.txt  lines like: domain | ip | org
Output: org|domaincount CSV (thresholded)

Large sets are spilled to disk and deduplicated using external sort.

Example:
  python -m hosterbench.counts.unique_slds --config config/pipeline.yaml
"""

import os
import csv
import re
import sys
import yaml
import json
import glob
import tempfile
import subprocess
import logging
from collections import defaultdict

from publicsuffix2 import get_sld

csv.field_size_limit(10**7)
logger = logging.getLogger("step3.unique_slds")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    logger.addHandler(h)
logger.setLevel(logging.INFO)

# ---------------------------
# Helpers
# ---------------------------

def to_sld(domain: str):
    try:
        return get_sld(domain.strip().lower().rstrip("."))
    except Exception:
        return None

def _is_probably_json_list(s: str) -> bool:
    s = (s or "").strip()
    return (s.startswith("[") and s.endswith("]")) or (s.startswith("(") and s.endswith(")"))

def _parse_cidr_list(raw: str):
    """
    Parse a list of CIDRs from flexible cell content.
    Accepts JSON/Python list strings or comma/pipe separated.
    """
    if raw is None:
        return []
    s = str(raw).strip()
    if not s:
        return []
    # try JSON first
    try:
        v = json.loads(s)
        if isinstance(v, (list, tuple)):
            return [str(x).strip() for x in v if x]
    except Exception:
        pass
    # try python literal
    try:
        import ast
        v = ast.literal_eval(s)
        if isinstance(v, (list, tuple)):
            return [str(x).strip() for x in v if x]
    except Exception:
        pass
    # delimiter fallback
    if "|" in s and not _is_probably_json_list(s):
        parts = [p.strip().strip("'").strip('"') for p in s.split("|")]
        return [p for p in parts if p]
    if "," in s and not _is_probably_json_list(s):
        parts = [p.strip().strip("'").strip('"') for p in s.split(",")]
        return [p for p in parts if p]
    # regex last resort (IPv4 only)
    cidr_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
    return cidr_re.findall(s)

def load_hoster_cidrs(path: str) -> dict:
    """
    Return dict: {Organization: [cidrs...]}
    Supports:
      - pipe text:   name | ... | ["1.2.3.0/24", ...]
      - CSV (, or |): columns Organization + cidrs/ranges/prefixes
      - YAML:
          hosters:
            - name: Example
              prefixes: [...]
    """
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"CIDR map file not found: {path}")

    lower = path.lower()

    # YAML
    if lower.endswith((".yml", ".yaml")):
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        out = {}
        for item in (data.get("hosters") or []):
            name = str(item.get("name", "")).strip()
            prefs = [p.strip() for p in (item.get("prefixes") or []) if p]
            if name and prefs:
                out[name] = sorted(set(prefs))
        return out

    # Peek first non-empty line
    def first_line(p):
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                t = line.strip()
                if t:
                    return t
        return ""

    head = first_line(path)

    # CSV with header (comma or pipe)
    if ("," in head) or ("|" in head and head.count("|") >= 1 and head.lower().replace(" ", "").startswith("organization")):
        with open(path, "r", encoding="utf-8", errors="ignore", newline="") as fh:
            # Sniff delimiter cheaply
            delim = "," if "," in head and "|" not in head else "|"
            rdr = csv.DictReader(fh, delimiter=delim)
            # normalize keys
            rows = []
            for row in rdr:
                if not row:
                    continue
                rows.append({(k or "").strip(): (v or "").strip() for k, v in row.items()})
            # pick columns
            name_col = None
            for c in ("Organization", "org", "hoster", "name"):
                if rows and c in rows[0]:
                    name_col = c
                    break
            cidr_col = None
            for c in ("cidrs", "ranges", "prefixes", "prefix"):
                if rows and c in rows[0]:
                    cidr_col = c
                    break
            if not name_col or not cidr_col:
                # fall back to heuristic on any row
                if rows:
                    keys = list(rows[0].keys())
                else:
                    keys = []
                raise ValueError(f"CSV CIDR map missing expected columns; got: {keys}")
            out = defaultdict(list)
            for r in rows:
                name = r.get(name_col, "")
                raw = r.get(cidr_col, "")
                cidrs = _parse_cidr_list(raw)
                if name and cidrs:
                    out[name].extend(cidrs)
            return {k: sorted(set(v)) for k, v in out.items()}

    # Pipe text (3rd column contains list)
    out = defaultdict(list)
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 3:
                continue
            name, ranges_raw = parts[0], parts[2]
            cidrs = _parse_cidr_list(ranges_raw)
            if name and cidrs:
                out[name].extend(cidrs)
    return {k: sorted(set(v)) for k, v in out.items()}

# ---------------------------
# Core Step 3
# ---------------------------

def count_unique_slds(config_path: str):
    """
    Reads step2 enriched files, counts unique SLDs per org, joins CIDRs, writes:
      Organization|domaincount|cidrs
    """
    import yaml as _yaml
    with open(config_path, "r", encoding="utf-8") as fh:
        cfg = _yaml.safe_load(fh) or {}

    paths = cfg.get("paths", {})
    inputs_glob = os.path.join(paths.get("step2_out_dir", ""), "step3_enriched_*")
    tmpdir = paths.get("tmpdir_step3", "data/work/tmp_step3")
    os.makedirs(tmpdir, exist_ok=True)

    outputs = cfg.get("outputs", {})
    out_csv = outputs.get("orgs_over_threshold")
    if not out_csv:
        raise ValueError("Missing outputs.orgs_over_threshold in pipeline config")
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)

    threshold = int(cfg.get("params", {}).get("threshold_sld_count", 100))
    files = sorted(glob.glob(inputs_glob))
    if not files:
        logger.info("Step3: no input files found (glob: %s)", inputs_glob)

    logger.info("Step3: Counting SLDs from %d files with 1 process(es)", len(files))

    # org -> set(SLD)
    org_slds = defaultdict(set)
    tmpfiles = []

    def flush():
        if not org_slds:
            return
        tmp = tempfile.NamedTemporaryFile(delete=False, dir=tmpdir, prefix="flush_", suffix=".txt")
        with open(tmp.name, "w", encoding="utf-8") as out:
            for org, slds in org_slds.items():
                for s in slds:
                    out.write(f"{org}|{s}\n")
        tmpfiles.append(tmp.name)
        org_slds.clear()

    # read enriched lines: "domain | ip | org"
    for path in files:
        logger.info("[{}] processing".format(os.path.basename(path)))
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "|" not in line:
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) < 3:
                    continue
                domain, _ip, org = parts[0], parts[1], parts[2]
                sld = to_sld(domain)
                if org and sld:
                    org_slds[org].add(sld)
        flush()

    logger.info("Step3: Flushed to %d temp files", len(tmpfiles))

    # Merge + dedup globally
    merged = os.path.join(tmpdir, "all_pairs.txt")
    sorted_unique = os.path.join(tmpdir, "all_pairs_unique.txt")

    logger.info("Merging temp files...")
    with open(merged, "w", encoding="utf-8") as out:
        for tf in tmpfiles:
            with open(tf, "r", encoding="utf-8") as f:
                for line in f:
                    out.write(line)
            os.remove(tf)

    logger.info("Deduplicating via external sort...")
    subprocess.run(["sort", "-u", "-T", tmpdir, "-S", "1G", merged, "-o", sorted_unique], check=True)
    os.remove(merged)

    # Count per org
    logger.info("Counting per org...")
    counts = defaultdict(int)
    if os.path.exists(sorted_unique):
        with open(sorted_unique, "r", encoding="utf-8") as f:
            for line in f:
                org, _sld = line.strip().split("|", 1)
                counts[org] += 1
        os.remove(sorted_unique)

    # Load CIDR map and attach cidrs column
    cidr_map_path = paths.get("cidr_map")
    if not cidr_map_path:
        raise ValueError("paths.cidr_map is required so Step 3 can embed CIDRs in its output")
    hoster_cidrs = load_hoster_cidrs(cidr_map_path)

    # Write final CSV (pipe-delimited)
    with open(out_csv, "w", newline="", encoding="utf-8") as out:
        w = csv.writer(out, delimiter="|")
        w.writerow(["Organization", "domaincount", "cidrs"])
        for org, count in sorted(counts.items(), key=lambda x: -x[1]):
            if count >= threshold:
                cidrs = hoster_cidrs.get(org, [])
                w.writerow([org, count, json.dumps(cidrs, ensure_ascii=False)])

    logger.info("Step3: Wrote %s", out_csv)

# CLI shim (optional)
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Step 3: Count unique SLDs and include CIDR lists")
    ap.add_argument("--config", required=True, help="pipeline.yaml")
    args = ap.parse_args()
    count_unique_slds(args.config)

#!/usr/bin/env python3
"""
Step 3 — Count SLD occurrences per org (NO DEDUPLICATION).

Input (glob):   data/work/step2/step3_enriched_*
Each line:      "<domain> | <ip> | <org>"

Output (pipe CSV): outputs.orgs_over_threshold
Columns:        Organization|domaincount|cidrs

Notes:
- Every line contributes +1 to its organization's count once converted to an SLD.
- There is absolutely NO deduplication. Repeated domain/org pairs or repeated SLDs
  are all counted again.
- CIDRs are loaded from paths.cidr_map and can be MaxMind-style:
    Organization|Ranges|[Size]|[Country_hist]
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import logging
import os
import re
from collections import defaultdict
from typing import Dict, List

try:
    from publicsuffix2 import get_sld
except Exception:
    get_sld = None

# ---------- logging ----------
logger = logging.getLogger("step3.sld_counts_nodedup")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(_handler)

csv.field_size_limit(10**7)

# ---------- helpers ----------

def to_sld(domain: str) -> str | None:
    if not domain:
        return None
    d = domain.strip().lower().rstrip(".")
    if not d:
        return None
    if get_sld:
        try:
            return get_sld(d)
        except Exception:
            return None
    # fallback: last two labels
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


CIDR_V4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")

def _parse_range_list_value(raw: str) -> List[str]:
    """Flexible parser for a cell containing CIDR ranges."""
    if raw is None:
        return []
    s = str(raw).strip()
    if not s:
        return []

    # Try JSON array
    try:
        v = json.loads(s)
        if isinstance(v, (list, tuple)):
            return [str(x).strip() for x in v if x]
    except Exception:
        pass

    # Try Python literal
    try:
        import ast
        v = ast.literal_eval(s)
        if isinstance(v, (list, tuple)):
            return [str(x).strip() for x in v if x]
    except Exception:
        pass

    # Delimited strings
    if "|" in s:
        parts = [p.strip().strip("'").strip('"') for p in s.split("|")]
        cand = [p for p in parts if p]
        if cand:
            return cand
    if "," in s:
        parts = [p.strip().strip("'").strip('"') for p in s.split(",")]
        cand = [p for p in parts if p]
        if cand:
            return cand

    # Regex fallback (IPv4 only)
    return CIDR_V4_RE.findall(s)


def load_hoster_cidrs(path: str) -> Dict[str, List[str]]:
    """
    Load hoster->CIDRs map from CSV/pipe file.

    Supports MaxMind-like:
      Organization | Ranges | [Size] | [Country_hist]

    Also supports legacy: hoster/name + cidrs/prefixes/prefix.
    """
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"CIDR map not found: {path}")

    # Detect delimiter by header line
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        head = ""
        for line in fh:
            if line.strip():
                head = line.strip()
                break
    delim = "|" if head.count("|") >= head.count(",") else ","

    out = defaultdict(list)
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as fh:
        rdr = csv.DictReader(fh, delimiter=delim)
        headers = [h.strip() for h in (rdr.fieldnames or [])]
        lowmap = {h.lower(): h for h in headers}

        # Column selection (case-insensitive)
        name_col = (
            lowmap.get("organization")
            or lowmap.get("org")
            or lowmap.get("hoster")
            or lowmap.get("name")
        )
        cidr_col = (
            lowmap.get("ranges")
            or lowmap.get("cidrs")
            or lowmap.get("prefixes")
            or lowmap.get("prefix")
        )

        if not name_col or not cidr_col:
            raise ValueError(
                f"CSV CIDR map missing expected columns; got: {headers}"
            )

        for row in rdr:
            if not row:
                continue
            org = (row.get(name_col) or "").strip()
            raw_ranges = row.get(cidr_col)
            if not org or raw_ranges is None:
                continue
            cidrs = _parse_range_list_value(raw_ranges)
            if cidrs:
                out[org].extend(cidrs)

    return {k: sorted(set(v)) for k, v in out.items()}


# ---------- core step (NO DEDUP) ----------

def count_sld_occurrences_from_args(
    inputs_glob: str,
    out_csv: str,
    threshold: int,
    cidr_map_path: str | None,
) -> None:
    """
    Scan enriched files and count SLD occurrences per org.
    No deduplication at all: every line increments its org by +1 if an SLD is derived.
    """
    files = sorted(glob.glob(inputs_glob))
    if not files:
        logger.info(f"Step3: no input files found (glob: {inputs_glob})")

    logger.info(f"Step3: Counting SLD occurrences from {len(files)} files (no dedup)")

    counts: Dict[str, int] = defaultdict(int)

    for path in files:
        logger.info(f"[{os.path.basename(path)}] processing")
        opener = open
        if path.endswith(".gz"):
            import gzip
            opener = lambda p, *a, **k: gzip.open(p, "rt", encoding="utf-8", errors="replace")
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "|" not in line:
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) < 3:
                    continue
                domain, _ip, org = parts[0], parts[1], parts[2]
                sld = to_sld(domain)
                if org and sld:
                    counts[org] += 1  # <-- NO DEDUP: count every occurrence

    _write_output(counts, out_csv, cidr_map_path, threshold)
    logger.info(f"Step3: Wrote {out_csv}")


def _write_output(
    counts: Dict[str, int],
    out_csv: str,
    cidr_map_path: str | None,
    threshold: int,
) -> None:
    """
    Write pipe-delimited CSV: Organization|domaincount|cidrs
    """
    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)

    # Load CIDRs (optional but recommended; Step 4 expects 'cidrs' column)
    cidrs_by_org: Dict[str, List[str]] = {}
    if cidr_map_path and os.path.exists(cidr_map_path):
        try:
            cidrs_by_org = load_hoster_cidrs(cidr_map_path)
        except Exception as e:
            logger.warning(f"Could not load CIDR map from {cidr_map_path}: {e}")

    with open(out_csv, "w", newline="", encoding="utf-8") as out:
        w = csv.writer(out, delimiter="|")
        w.writerow(["Organization", "domaincount", "cidrs"])
        for org, cnt in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
            if cnt >= threshold:
                cidrs = cidrs_by_org.get(org, [])
                # store as JSON array to keep a single cell
                cidr_cell = json.dumps(cidrs, ensure_ascii=False)
                w.writerow([org, cnt, cidr_cell])


# ---------- CLI / config ----------

def count_unique_slds(config_path: str):
    """
    Retains CLI/API compatibility with previous name but now counts occurrences
    (no dedup). Reads YAML config and runs the step.
    """
    try:
        import yaml as _yaml
    except ImportError as e:
        raise RuntimeError("Install pyyaml: pip install pyyaml") from e

    with open(config_path, "r", encoding="utf-8") as fh:
        cfg = _yaml.safe_load(fh) or {}

    paths = cfg.get("paths", {}) or {}
    outputs = cfg.get("outputs", {}) or {}
    params = cfg.get("params", {}) or {}

    inputs_glob = os.path.join(paths.get("step2_out_dir", "data/work/step2"), "step3_enriched_*")
    out_csv = outputs.get("orgs_over_threshold", "data/output/orgs.csv")
    threshold = int(params.get("threshold_sld_count", 100))
    cidr_map_path = paths.get("cidr_map")

    if not cidr_map_path:
        logger.warning("paths.cidr_map is not set; 'cidrs' column will be empty.")

    count_sld_occurrences_from_args(inputs_glob, out_csv, threshold, cidr_map_path)


def main():
    ap = argparse.ArgumentParser(description="Step 3: Count SLD occurrences per org (no dedup).")
    ap.add_argument("--inputs", default="data/work/step2/step3_enriched_*", help="Glob for Step 2 outputs")
    ap.add_argument("--out", default="data/output/orgs.csv", help="Output pipe-delimited CSV")
    ap.add_argument("--threshold", type=int, default=100, help="Minimum count to include")
    ap.add_argument("--cidr-map", default=None, help="Path to hosters CIDR map (Organization|Ranges|...)")
    args = ap.parse_args()

    count_sld_occurrences_from_args(args.inputs, args.out, args.threshold, args.cidr_map)


if __name__ == "__main__":
    main()

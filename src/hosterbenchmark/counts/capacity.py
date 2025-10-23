#!/usr/bin/env python3
"""
Step 4 — Compute IP capacity for each organization from CIDRs

Input:  CSV with org + CIDR list + domaincount
Output: CSV with IP capacity metrics per org

Columns:
  - Organization
  - domaincount
  - cidr_count
  - total_ips
  - avg_domains_per_ip
  - cidrs (JSON string)

Example:
  python -m hosterbench.counts.capacity --config config/pipeline.yaml
"""

import re
import ast
import json
import ipaddress
import pandas as pd
import argparse
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None

CIDR_RE_V4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
CIDR_RE_V6 = re.compile(r"\b[0-9A-Fa-f:]+/\d{1,3}\b")

def safe_parse_ranges(s: str, include_ipv6: bool = False):
    """Return clean list of CIDRs from a stringified list or messy text."""
    if not isinstance(s, str) or not s.strip():
        return []

    s = s.strip().replace('""', '"')
    try:
        v = ast.literal_eval(s)
        if isinstance(v, (list, tuple)):
            cand = [str(x).strip().strip('"').strip("'") for x in v]
        else:
            cand = None
    except Exception:
        cand = None

    if cand is None:
        cand = CIDR_RE_V4.findall(s)
        if include_ipv6:
            cand += CIDR_RE_V6.findall(s)

    out, seen = [], set()
    for c in cand:
        try:
            net = ipaddress.ip_network(c.strip(), strict=False)
            if not include_ipv6 and isinstance(net, ipaddress.IPv6Network):
                continue
            norm = str(net)
            if norm not in seen:
                seen.add(norm)
                out.append(norm)
        except Exception:
            continue
    return out

def cidr_count_addrs(cidrs, include_ipv6=False):
    """Return (number of CIDRs, total IPs)"""
    total = 0
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
            if not include_ipv6 and isinstance(net, ipaddress.IPv6Network):
                continue
            total += net.num_addresses
        except Exception:
            pass
    return len(cidrs), total

def compute_capacity_from_args(input_csv: str, output_csv: str, include_ipv6: bool = False):
    df = pd.read_csv(input_csv, sep="|")

    # Ensure needed columns
    required = {"Organization", "domaincount"}
    if not required.issubset(df.columns):
        raise ValueError(f"Missing columns in input: {required - set(df.columns)}")

    # Parse CIDR field
    range_field = None
    for col in df.columns:
        if col.lower() in {"cidrs", "ranges", "prefixes"}:
            range_field = col
            break
    if not range_field:
        raise ValueError("Input must contain a CIDR field like 'cidrs', 'ranges', or 'prefixes'")

    df["domaincount"] = pd.to_numeric(df["domaincount"], errors="coerce").fillna(0).astype(int)

    df["_cidr_list"] = df[range_field].apply(lambda s: safe_parse_ranges(s, include_ipv6))
    stats = df["_cidr_list"].apply(lambda lst: cidr_count_addrs(lst, include_ipv6))
    df["cidr_count"] = stats.apply(lambda x: x[0])
    df["total_ips"] = stats.apply(lambda x: x[1])
    df["avg_domains_per_ip"] = df.apply(
        lambda r: (r["domaincount"] / r["total_ips"]) if r["total_ips"] > 0 else 0.0,
        axis=1
    )
    df["cidrs"] = df["_cidr_list"].apply(lambda lst: json.dumps(lst, ensure_ascii=False))

    out_cols = [
        "Organization",
        "domaincount",
        "cidr_count",
        "total_ips",
        "avg_domains_per_ip",
        "cidrs"
    ]
    out = df[out_cols].sort_values("domaincount", ascending=False)
    out.to_csv(output_csv, index=False)
    print(f"✅ Wrote {len(out)} organizations to {output_csv}")

def _load_yaml_config(cfg_path: str) -> dict:
    if yaml is None:
        raise RuntimeError("PyYAML not installed. Use CLI flags or install pyyaml")
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}

def compute_capacity(config_path: Optional[str] = None):
    if not config_path:
        raise ValueError("Missing config_path")

    cfg = _load_yaml_config(config_path)
    paths = cfg.get("paths", {})
    params = cfg.get("params", {})
    outputs = cfg.get("outputs", {})

    input_csv = outputs.get("orgs_over_threshold")
    output_csv = outputs.get("capacity_csv", "data/output/org_ip_capacity.csv")
    include_ipv6 = bool(params.get("include_ipv6", False))

    if not input_csv:
        raise ValueError("Missing outputs.orgs_over_threshold in pipeline config")

    compute_capacity_from_args(input_csv, output_csv, include_ipv6)

def main():
    ap = argparse.ArgumentParser(description="Step 4: Compute IP capacity from CIDRs")
    ap.add_argument("--input", required=False, help="CSV with domaincount + CIDRs")
    ap.add_argument("--output", default="data/output/org_ip_capacity.csv")
    ap.add_argument("--include-ipv6", action="store_true")
    ap.add_argument("--config", help="YAML pipeline config")
    args = ap.parse_args()

    if args.config:
        compute_capacity(args.config)
        return

    if not args.input:
        ap.error("Must provide --input or --config")

    compute_capacity_from_args(args.input, args.output, args.include_ipv6)

if __name__ == "__main__":
    main()

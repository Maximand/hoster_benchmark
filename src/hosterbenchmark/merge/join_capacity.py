#!/usr/bin/env python3
"""
Step 6 — Merge abuse feed counts with capacity metrics

Input:
  - hoster_abuse_counts.csv (from LMDB step)
  - org_ip_capacity.csv (from CIDR step)

Output:
  - merged_counts_with_capacity.csv

Usage:
  python -m hosterbench.merge.join_capacity --config config/pipeline.yaml
"""

import argparse
import pandas as pd
import yaml

def pick_left_key(df):
    if "hoster" in df.columns:
        return "hoster"
    if "Organization" in df.columns:
        return "Organization"
    raise ValueError("Feed counts file must contain 'hoster' or 'Organization' as a join key")

def pick_right_key(df):
    if "Organization" in df.columns:
        return "Organization"
    if "org" in df.columns:
        return "org"
    raise ValueError("Capacity file must contain 'Organization' or 'org' as a join key")

def merge_feeds_and_capacity(
    feeds_path: str,
    capacity_path: str,
    output_path: str,
    fill_ipcount_seen: bool = False
):
    df_feeds = pd.read_csv(feeds_path)
    df_cap = pd.read_csv(capacity_path)

    left_key = pick_left_key(df_feeds)
    right_key = pick_right_key(df_cap)

    # Normalize for join safety
    df_feeds[left_key] = df_feeds[left_key].astype(str).str.strip()
    df_cap[right_key] = df_cap[right_key].astype(str).str.strip()

    # Select only required columns from capacity
    keep_cols = [right_key, "domaincount", "cidr_count", "total_ips", "avg_domains_per_ip", "cidrs"]
    missing = [col for col in keep_cols if col not in df_cap.columns]
    if missing:
        raise ValueError(f"Missing columns in capacity file: {missing}")

    cap_sub = df_cap[keep_cols].copy()

    # Perform LEFT JOIN
    merged = df_feeds.merge(cap_sub, left_on=left_key, right_on=right_key, how="left")

    # Drop extra join column if needed
    if left_key != right_key and right_key in merged.columns:
        merged.drop(columns=[right_key], inplace=True)

    # Recalculate avg if missing or NaN
    if "avg_domains_per_ip" not in merged.columns or merged["avg_domains_per_ip"].isna().all():
        merged["avg_domains_per_ip"] = merged.apply(
            lambda r: (r["domaincount"] / r["total_ips"])
            if pd.notna(r.get("total_ips")) and r.get("total_ips", 0) > 0
            else 0.0,
            axis=1
        )

    # Optional backfill for ipcount_seen
    if fill_ipcount_seen:
        if "ipcount_seen" not in merged.columns:
            merged["ipcount_seen"] = merged["total_ips"]
        else:
            merged["ipcount_seen"] = merged["ipcount_seen"].where(
                merged["ipcount_seen"].notna(), merged["total_ips"]
            )

    merged.to_csv(output_path, index=False)
    print(f"Merged dataset written to {output_path} ({len(merged)} rows)")

def merge_counts(config_path: str):
    with open(config_path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    feeds_path = cfg["outputs"]["hoster_counts_csv"]
    capacity_path = cfg["outputs"]["capacity_csv"]
    out_path = cfg["outputs"]["merged_csv"]

    df_feeds = pd.read_csv(feeds_path)
    df_cap = pd.read_csv(capacity_path)

    # Determine join keys
    left_key = "hoster" if "hoster" in df_feeds.columns else "Organization"
    right_key = "Organization" if "Organization" in df_cap.columns else "org"

    # Subset capacity columns
    keep_cols = [right_key, "domaincount", "cidr_count", "total_ips", "avg_domains_per_ip", "cidrs"]
    cap_sub = df_cap[keep_cols].copy()

    merged = df_feeds.merge(cap_sub, left_on=left_key, right_on=right_key, how="left")

    if left_key != right_key and right_key in merged.columns:
        merged = merged.drop(columns=[right_key])

    merged["avg_domains_per_ip"] = merged.apply(
        lambda r: (r["domaincount"] / r["total_ips"]) if pd.notna(r.get("total_ips")) and r.get("total_ips", 0) > 0 else 0.0,
        axis=1
    )

    merged.to_csv(out_path, index=False)
    print(f"Wrote merged results to {out_path}")

def _load_yaml_config(path: str) -> dict:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def main():
    ap = argparse.ArgumentParser(description="Step 6: Merge feed data with capacity estimates")
    ap.add_argument("--feeds", help="CSV from LMDB step (e.g. hoster_abuse_counts.csv)")
    ap.add_argument("--capacity", help="CSV from CIDR step (e.g. org_ip_capacity.csv)")
    ap.add_argument("--out", default="data/output/merged_counts_with_capacity.csv")
    ap.add_argument("--fill-ipcount-seen", action="store_true", help="Backfill ipcount_seen from total_ips if missing")
    ap.add_argument("--config", help="YAML config file")

    args = ap.parse_args()

    if args.config:
        cfg = _load_yaml_config(args.config)
        feeds_path = cfg["outputs"]["hoster_counts_csv"]
        capacity_path = cfg["outputs"]["capacity_csv"]
        output_path = cfg["outputs"].get("merged_counts_csv", "data/output/merged_counts_with_capacity.csv")
        fill = cfg.get("params", {}).get("fill_ipcount_seen", False)
    else:
        feeds_path = args.feeds
        capacity_path = args.capacity
        output_path = args.out
        fill = args.fill_ipcount_seen

    merge_feeds_and_capacity(feeds_path, capacity_path, output_path, fill)

if __name__ == "__main__":
    main()

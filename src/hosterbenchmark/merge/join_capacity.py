#!/usr/bin/env python3
"""
Step 6 — Merge capacity and feed metrics into one unified CSV.

Inputs (from pipeline.yaml):
  - outputs.capacity_csv
  - outputs.hoster_counts_csv

Output:
  - outputs.merged_csv
"""

from __future__ import annotations
import os
import pandas as pd
import logging

logger = logging.getLogger("hosterbenchmark.step6")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(_handler)


def merge_counts(cfg: dict) -> None:
    """Merge capacity and feed CSVs, dropping redundant identical columns."""
    outputs = cfg.get("outputs", {}) or {}
    cap_path = outputs.get("capacity_csv")
    feed_path = outputs.get("hoster_counts_csv")
    out_path = outputs.get("merged_csv")

    if not cap_path or not feed_path or not out_path:
        raise ValueError("pipeline.yaml missing one of outputs.{capacity_csv, hoster_counts_csv, merged_csv}")

    if not os.path.isfile(cap_path):
        raise FileNotFoundError(f"Missing capacity file: {cap_path}")
    if not os.path.isfile(feed_path):
        raise FileNotFoundError(f"Missing feed file: {feed_path}")

    logger.info(f"Step 6: reading {cap_path} and {feed_path}")
    cap_df = pd.read_csv(cap_path)
    feed_df = pd.read_csv(feed_path)

    # normalize key names for join
    for df in (cap_df, feed_df):
        if "Organization" not in df.columns and "hoster" in df.columns:
            df.rename(columns={"hoster": "Organization"}, inplace=True)

    # perform outer merge
    merged = pd.merge(cap_df, feed_df, on="Organization", how="outer", suffixes=("_x", "_y"))

    # detect duplicate columns and drop identical ones
    to_drop = []
    for col in merged.columns:
        if col.endswith("_x"):
            base = col[:-2]
            twin = base + "_y"
            if twin in merged.columns:
                if merged[col].equals(merged[twin]):
                    to_drop.append(twin)
                else:
                    logger.warning(f"Column '{base}' differs between capacity and feeds; keeping both")

    if to_drop:
        logger.info(f"Dropping {len(to_drop)} redundant identical columns: {', '.join(to_drop[:6])}{'...' if len(to_drop)>6 else ''}")
        merged.drop(columns=to_drop, inplace=True)

    merged.to_csv(out_path, index=False)
    logger.info(f"Step 6: wrote {out_path} ({len(merged)} rows, {len(merged.columns)} columns)")


def main():
    import argparse, yaml
    ap = argparse.ArgumentParser(description="Step 6: Merge capacity and feed metrics")
    ap.add_argument("--config", required=True, help="Path to pipeline.yaml")
    args = ap.parse_args()
    with open(args.config, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    merge_pipeline(cfg)


if __name__ == "__main__":
    main()

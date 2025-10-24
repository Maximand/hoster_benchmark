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
import logging
from typing import Union, Dict, Any
import pandas as pd

try:
    import yaml
except Exception:
    yaml = None

logger = logging.getLogger("hosterbenchmark.step6")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(_handler)


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _load_cfg(config_path_or_dict: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Accept either a config dict or a path to YAML and return a dict."""
    if isinstance(config_path_or_dict, dict):
        return config_path_or_dict
    if not isinstance(config_path_or_dict, str):
        raise TypeError("merge_counts() expected a dict or path to pipeline.yaml")

    if yaml is None:
        raise RuntimeError("pyyaml is required to read YAML config files")

    if not os.path.isfile(config_path_or_dict):
        raise FileNotFoundError(f"pipeline.yaml not found: {config_path_or_dict}")

    with open(config_path_or_dict, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    return cfg


def _normalize_join_key(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure both inputs join on 'Organization'."""
    if "Organization" not in df.columns and "hoster" in df.columns:
        df = df.rename(columns={"hoster": "Organization"})
    return df


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def merge_counts(config_path_or_dict: Union[str, Dict[str, Any]]) -> None:
    """
    Merge capacity and feed CSVs, dropping redundant identical columns
    and cleaning suffixes (_x/_y).
    """
    cfg = _load_cfg(config_path_or_dict)
    outputs = cfg.get("outputs", {}) or {}

    cap_path = outputs.get("capacity_csv")
    feed_path = outputs.get("hoster_counts_csv") or outputs.get("feeds_csv")
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

    cap_df = _normalize_join_key(cap_df)
    feed_df = _normalize_join_key(feed_df)

    if "Organization" not in cap_df.columns or "Organization" not in feed_df.columns:
        raise ValueError("Neither input contains 'Organization' (or 'hoster') to join on.")

    merged = pd.merge(cap_df, feed_df, on="Organization", how="outer", suffixes=("_x", "_y"))

    # Drop redundant identical *_y columns; keep *_x and rename it back
    to_drop = []
    to_rename = {}
    for col in merged.columns:
        if col.endswith("_x"):
            base = col[:-2]
            twin = base + "_y"
            if twin in merged.columns:
                if merged[col].equals(merged[twin]):
                    to_drop.append(twin)
                    to_rename[col] = base  # rename the kept _x column back to original
                else:
                    logger.warning(f"Column '{base}' differs between capacity and feeds; keeping both")
            else:
                # no twin, rename to base anyway for clarity
                to_rename[col] = base

    if to_drop:
        logger.info(f"Dropping {len(to_drop)} redundant identical columns: {', '.join(to_drop[:6])}{'...' if len(to_drop)>6 else ''}")
        merged.drop(columns=to_drop, inplace=True)

    if to_rename:
        merged.rename(columns=to_rename, inplace=True)

    # Final cleanup: drop any lingering '_y' columns that were unmatched but empty
    y_cols = [c for c in merged.columns if c.endswith("_y") and merged[c].isna().all()]
    if y_cols:
        logger.info(f"Dropping empty trailing columns: {', '.join(y_cols)}")
        merged.drop(columns=y_cols, inplace=True)

    # Write output
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    merged.to_csv(out_path, index=False)
    logger.info(f"Step 6: wrote {out_path} ({len(merged)} rows, {len(merged.columns)} columns)")


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Step 6: Merge capacity and feed metrics")
    ap.add_argument("--config", required=True, help="Path to pipeline.yaml")
    args = ap.parse_args()
    merge_counts(args.config)


if __name__ == "__main__":
    main()

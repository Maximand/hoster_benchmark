"""
Feed parser registry and helpers for HosterBenchmark (Step 5).

This module provides:
- FEED_REGISTRY: mapping of feed names → parser functions
- @register_feed decorator for adding new parsers
- load_hosters(): load hoster → prefix mappings from text/CSV/YAML
- _expand_files(): glob path expansion utility
"""

import csv
import glob
import os
import re
from typing import List, Dict, Callable

# --- Feed registry and decorator ---------------------------------------------

FEED_REGISTRY: Dict[str, Callable] = {}

def register_feed(name: str):
    """
    Decorator to register a feed parser.
    Usage:

        @register_feed("apwg_csv_ip")
        def parse_apwg_csv_ip(line: str) -> list[str]:
            ...
            return [ip1, ip2]
    """
    def decorator(func: Callable):
        FEED_REGISTRY[name] = func
        return func
    return decorator

# --- Utility: expand glob paths ----------------------------------------------

def _expand_files(pathlike: str) -> List[str]:
    """
    Expand directory or glob pattern into sorted list of files.
    """
    if os.path.isdir(pathlike):
        return [
            os.path.join(pathlike, f)
            for f in sorted(os.listdir(pathlike))
            if os.path.isfile(os.path.join(pathlike, f))
        ]
    matches = sorted(glob.glob(pathlike, recursive=True))
    return [m for m in matches if os.path.isfile(m)]

# --- Utility: load hosters ---------------------------------------------------

def load_hosters(path: str, delimiter: str = "|", comment_prefix: str = "#") -> Dict[str, List[str]]:
    """
    Load hosters from a simple pipe-delimited or CSV file.

    Returns a dict:
        { "TransIP": ["prefix1", "prefix2"], "OVH": ["prefix3", ...] }

    Compatible formats:
        name|prefix1,prefix2
        name|["prefix1","prefix2"]
        # comments are ignored
    """
    hosters: Dict[str, List[str]] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f, delimiter=delimiter)
        for row in reader:
            if not row or row[0].startswith(comment_prefix):
                continue
            name = row[0].strip()
            if not name:
                continue
            prefixes: List[str] = []
            if len(row) > 1 and row[1].strip():
                raw = row[1].strip()
                # parse list-like strings
                if raw.startswith("[") and raw.endswith("]"):
                    raw = raw.strip("[]")
                    prefixes = [p.strip().strip("'\"") for p in raw.split(",") if p.strip()]
                elif "," in raw:
                    prefixes = [p.strip() for p in raw.split(",") if p.strip()]
                else:
                    prefixes = [raw]
            hosters[name] = prefixes
    return hosters

# --- Example built-in parsers ------------------------------------------------

@register_feed("apwg_csv_ip")
def parse_apwg_csv_ip(line: str) -> List[str]:
    """
    Parse APWG CSV (no header, IPs in 4th column).
    Returns list of IPv4 strings.
    """
    parts = line.strip().split(",")
    if len(parts) < 4:
        return []
    # Example column 3: "[u'1.2.3.4', u'5.6.7.8']"
    ip_field = parts[3]
    ips = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", ip_field)
    return ips

# Disable domain counting for this parser (IP-only)
parse_apwg_csv_ip.COUNT_DOMAINS = False

@register_feed("dshield_daily")
def parse_dshield_daily(line: str) -> List[str]:
    """
    Parse DShield daily_sources TSV (source IP in first column).
    """
    if not line or line.startswith("#") or line.lower().startswith("source ip"):
        return []
    parts = line.strip().split("\t")
    if not parts:
        return []
    ip = parts[0].strip()
    return [ip] if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip) else []

parse_dshield_daily.COUNT_DOMAINS = False


@register_feed("dummy_feed")
def parse_dummy_feed(line: str) -> list[str]:
    """
    CSV with header:
      timestamp,source_ip,feed_info
    Returns: [source_ip] if it looks like IPv4, else [].
    """
    s = line.strip()
    if not s or s.lower().startswith("timestamp"):
        return []
    parts = s.split(",")
    if len(parts) < 2:
        return []
    ip = parts[1].strip()
    # simple IPv4 check
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ip):
        return [ip]
    return []

# IP-only; don't count domains for this feed
parse_dummy_feed.COUNT_DOMAINS = False

# -----------------------------------------------------------------------------
# @register_feed("my_feed_name")
# def parse_my_feed(line: str) -> list[str]:
#     ...
#     return [ip1, ip2]
#
# parse_my_feed.COUNT_DOMAINS = False
# -----------------------------------------------------------------------------

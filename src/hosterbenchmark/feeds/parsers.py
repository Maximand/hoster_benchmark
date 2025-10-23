#!/usr/bin/env python3
"""
Feed parser framework + hosters loader.

Exports expected by runner:
  - FEED_REGISTRY
  - register_feed
  - BaseFeedParser
  - FeedRecord
  - _expand_files
  - load_hosters
"""

from __future__ import annotations
import os
import csv
import re
import ast
import json
import glob
from collections import namedtuple, defaultdict
from typing import Dict, List, Tuple, Optional, Iterable, Union

# ------------------------------
# Small utilities
# ------------------------------

FeedRecord = namedtuple("FeedRecord", ["domain", "ips", "timestamp", "source"])

def safe_ip(ip: str) -> Optional[str]:
    try:
        import ipaddress
        return str(ipaddress.ip_address(str(ip).strip()))
    except Exception:
        return None

def _expand_files(pathlike: str) -> List[str]:
    """
    Expand a pathlike into files. Supports:
      - directory (non-recursive listing)
      - glob patterns (including **)
      - direct file path
    """
    if os.path.isdir(pathlike):
        return [
            os.path.join(pathlike, f)
            for f in sorted(os.listdir(pathlike))
            if os.path.isfile(os.path.join(pathlike, f))
        ]
    matches = sorted(glob.glob(pathlike, recursive=True))
    return [m for m in matches if os.path.isfile(m)] or (
        [pathlike] if os.path.isfile(pathlike) else []
    )

# ------------------------------
# Parser framework + registry
# ------------------------------

class BaseFeedParser:
    """
    Implement iter_records(self, path) -> Iterable[FeedRecord].

    NAME: string identifier used in feeds.yaml.
    COUNT_DOMAINS: if False, core will NOT count domains for this feed (IP-only).
    """
    NAME = "base"
    COUNT_DOMAINS = True

    def iter_records(self, path: str) -> Iterable[FeedRecord]:
        raise NotImplementedError

FEED_REGISTRY: Dict[str, type[BaseFeedParser]] = {}

def register_feed(cls: type[BaseFeedParser]):
    if not getattr(cls, "NAME", None):
        raise ValueError("Parser class must define NAME")
    FEED_REGISTRY[cls.NAME] = cls
    return cls

# ------------------------------
# Hosters loader (MaxMind-friendly)
# ------------------------------

CIDR_V4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")

def _parse_range_list_value(raw: str) -> List[str]:
    """
    Parse a list of CIDRs from flexible cell content.

    Accepts:
      - JSON list:    '["1.2.3.0/24","4.5.6.0/22"]'
      - Python list:  "['1.2.3.0/24', '4.5.6.0/22']"
      - Delimited:    "1.2.3.0/24, 4.5.6.0/22" or "1.2.3.0/24 | 4.5.6.0/22"
      - Fallback:     regex extraction (IPv4)
    """
    if raw is None:
        return []
    s = str(raw).strip()
    if not s:
        return []

    # JSON
    try:
        v = json.loads(s)
        if isinstance(v, (list, tuple)):
            return [str(x).strip() for x in v if x]
    except Exception:
        pass

    # Python literal
    try:
        v = ast.literal_eval(s)
        if isinstance(v, (list, tuple)):
            return [str(x).strip() for x in v if x]
    except Exception:
        pass

    # Delimited
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

    # Regex fallback
    return CIDR_V4_RE.findall(s)

def load_hosters(
    path: str,
    *,
    return_meta: bool = False
) -> Union[Dict[str, List[str]], Tuple[Dict[str, List[str]], Dict[str, dict]]]:
    """
    Load a MaxMind-derived hosters file in *pipe* format.

    Flexible schema (header optional):
        Organization | Ranges | Size | Country_hist
        Zeimudo Networks Ltd.|['1.3.3.0/24','103.1.72.0/22']|1280|{'CN':256,'UA':1024}

    - Only 'Organization' and 'Ranges' are required.
    - 'Ranges' may be JSON/Python list or delimited string.
    - Extra columns are ignored unless return_meta=True.

    Returns:
      prefixes_by_org: { org: [cidrs...] }
      meta_by_org (optional): { org: { "Size": <int?>, "Country_hist": <dict|str>, ... } }
    """
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"Hosters file not found: {path}")

    prefixes_by_org: Dict[str, List[str]] = defaultdict(list)
    meta_by_org: Dict[str, dict] = {}

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        first = True
        header = None
        name_cols = None

        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split("|")]

            if first:
                first = False
                low = [p.lower() for p in parts]
                if "organization" in low and "ranges" in low:
                    header = [p.lower() for p in parts]
                    name_cols = {
                        "org": header.index("organization"),
                        "ranges": header.index("ranges"),
                    }
                    continue  # proceed to next line (actual data)
                else:
                    name_cols = None  # no header present

            if name_cols:
                try:
                    org = parts[name_cols["org"]]
                    ranges_raw = parts[name_cols["ranges"]]
                except Exception:
                    continue
                extra = {}
                # pick up common extra fields if header present
                try:
                    if "size" in header:
                        size_idx = header.index("size")
                        if size_idx < len(parts):
                            sval = parts[size_idx]
                            try:
                                extra["Size"] = int(sval.replace(",", ""))
                            except Exception:
                                extra["Size"] = sval
                    if "country_hist" in header:
                        ch_idx = header.index("country_hist")
                        if ch_idx < len(parts):
                            cval = parts[ch_idx]
                            try:
                                extra["Country_hist"] = ast.literal_eval(cval)
                            except Exception:
                                extra["Country_hist"] = cval
                except Exception:
                    pass
            else:
                # No header: assume Organization | Ranges | (optional extras)
                if len(parts) < 2:
                    continue
                org, ranges_raw = parts[0], parts[1]
                extra = {}
                if len(parts) >= 3:
                    try:
                        extra["Size"] = int(parts[2].replace(",", ""))
                    except Exception:
                        extra["Size"] = parts[2]
                if len(parts) >= 4:
                    try:
                        extra["Country_hist"] = ast.literal_eval(parts[3])
                    except Exception:
                        extra["Country_hist"] = parts[3]

            cidrs = _parse_range_list_value(ranges_raw)
            if not cidrs:
                continue

            prefixes_by_org[org].extend(cidrs)

            if return_meta:
                meta_by_org.setdefault(org, {}).update(
                    {k: v for k, v in extra.items() if v is not None}
                )

    prefixes_by_org = {k: sorted(set(v)) for k, v in prefixes_by_org.items()}
    if return_meta:
        return prefixes_by_org, meta_by_org
    return prefixes_by_org

# ------------------------------
# Example parser: dummy CSV (IP-only)
# ------------------------------

@register_feed
class DummyCSV_IPOnly(BaseFeedParser):
    """
    Dummy CSV feed used for tests:
      header: timestamp,source_ip,feed_info
    Emits one FeedRecord per row w/ a valid IPv4.
    """
    NAME = "dummy_feed"
    COUNT_DOMAINS = False  # IP-only

    def iter_records(self, path: str) -> Iterable[FeedRecord]:
        with open(path, "r", encoding="utf-8") as fh:
            rdr = csv.DictReader(fh)
            for row in rdr:
                raw_ip = (row.get("source_ip") or "").strip()
                ip = safe_ip(raw_ip)
                if not ip:
                    continue
                ts = None
                ts_raw = row.get("timestamp")
                if ts_raw:
                    # epoch or ISO8601 best-effort
                    try:
                        ts = int(ts_raw)
                    except Exception:
                        try:
                            from datetime import datetime
                            ts = int(datetime.fromisoformat(str(ts_raw).replace("Z","+00:00")).timestamp())
                        except Exception:
                            ts = None
                yield FeedRecord(domain=ip, ips=[ip], timestamp=ts, source=self.NAME)

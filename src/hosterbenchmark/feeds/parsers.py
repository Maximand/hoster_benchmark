import ast
import csv
import json
import os
import re
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Union

CIDR_V4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")

def _parse_range_list_value(raw: str) -> List[str]:
    """
    Parse a list of CIDRs from flexible cell content.
    Accepts:
      - JSON array: '["1.2.3.0/24","4.5.6.0/22"]'
      - Python list: "['1.2.3.0/24', '4.5.6.0/22']"
      - Delimited string: "1.2.3.0/24, 4.5.6.0/22" or "1.2.3.0/24 | 4.5.6.0/22"
      - Fallback regex for IPv4 CIDRs
    """
    if raw is None:
        return []
    s = str(raw).strip()
    if not s:
        return []

    # JSON list
    try:
        v = json.loads(s)
        if isinstance(v, (list, tuple)):
            return [str(x).strip() for x in v if x]
    except Exception:
        pass

    # Python literal list/tuple
    try:
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


def load_hosters(
    path: str,
    *,
    return_meta: bool = False
) -> Union[Dict[str, List[str]], Tuple[Dict[str, List[str]], Dict[str, dict]]]:
    """
    Load a MaxMind-derived hosters file in *pipe* format.

    Expected flexible schema (header optional):
        Organization | Ranges | Size | Country_hist
        Zeimudo Networks Ltd.|['1.3.3.0/24', '103.1.72.0/22']|1280|{'CN': 256, 'UA': 1024}

    - Only 'Organization' and 'Ranges' are required.
    - 'Ranges' may be JSON list, Python list, or a delimited string.
    - Extra columns are ignored unless return_meta=True.

    Returns:
        prefixes_by_org: dict { org: [cidrs...] }
        meta_by_org (optional): dict { org: { "Size": <int?>, "Country_hist": <dict|str> , ... } }
    """
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"Hosters file not found: {path}")

    prefixes_by_org: Dict[str, List[str]] = defaultdict(list)
    meta_by_org: Dict[str, dict] = {}

    # Read as plain text, split by pipe. Header optional.
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        first = True
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split("|")]
            # Heuristic: check header in the first non-empty line
            if first:
                first = False
                # header if it contains "organization" and "ranges" in some order
                low = [p.lower() for p in parts]
                if "organization" in low and "ranges" in low:
                    header = [p.lower() for p in parts]
                    org_idx = header.index("organization")
                    rng_idx = header.index("ranges")
                    # keep header info for named extraction
                    name_cols = { "org": org_idx, "ranges": rng_idx }
                    continue
                else:
                    # no header
                    name_cols = None

            if name_cols:
                try:
                    org = parts[name_cols["org"]]
                    ranges_raw = parts[name_cols["ranges"]]
                except Exception:
                    # malformed row vs header; skip
                    continue
                extra = {}
                # record any extra columns as metadata (best-effort)
                if len(parts) > 2:
                    # rebuild mapping by header indices if available
                    # otherwise index-based keys
                    # Here we only try common names
                    try:
                        # try to parse Size (int-like)
                        if "size" in header:
                            size_idx = header.index("size")
                            size_val = parts[size_idx]
                            try:
                                extra["Size"] = int(size_val.replace(",", "").strip())
                            except Exception:
                                extra["Size"] = size_val
                        # try to parse Country_hist (dict-like)
                        if "country_hist" in header:
                            ch_idx = header.index("country_hist")
                            ch_val = parts[ch_idx]
                            try:
                                extra["Country_hist"] = ast.literal_eval(ch_val)
                            except Exception:
                                extra["Country_hist"] = ch_val
                    except Exception:
                        pass
            else:
                # no header: assume Organization | Ranges | ...
                if len(parts) < 2:
                    continue
                org, ranges_raw = parts[0], parts[1]
                # capture extras as metadata (positional best-effort)
                extra = {}
                if len(parts) >= 3:
                    # Size (optional)
                    try:
                        extra["Size"] = int(parts[2].replace(",", "").strip())
                    except Exception:
                        extra["Size"] = parts[2]
                if len(parts) >= 4:
                    # Country_hist (optional, python-literal dict)
                    try:
                        extra["Country_hist"] = ast.literal_eval(parts[3])
                    except Exception:
                        extra["Country_hist"] = parts[3]

            # Parse ranges to CIDR list
            cidrs = _parse_range_list_value(ranges_raw)
            if not cidrs:
                continue
            prefixes_by_org[org].extend(cidrs)

            if return_meta:
                # merge metadata (if multiple rows per org)
                if org not in meta_by_org:
                    meta_by_org[org] = {}
                meta_by_org[org].update({k: v for k, v in extra.items() if v is not None})

    # Deduplicate & sort CIDRs
    prefixes_by_org = { org: sorted(set(v)) for org, v in prefixes_by_org.items() }

    if return_meta:
        return prefixes_by_org, meta_by_org
    return prefixes_by_org

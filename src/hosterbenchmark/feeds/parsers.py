from __future__ import annotations

import csv
import gzip
import io
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple, Callable, Any, Union

# --------------------------------------------------------------------------------------
# Registry & decorator
# --------------------------------------------------------------------------------------

FEED_REGISTRY: Dict[str, Any] = {}

def register_feed(cls):
    """
    Class decorator that registers a parser class (or instance) under cls.NAME.
    The class must implement:
      - NAME: str
      - COUNT_DOMAINS: bool
      - iter_records(path: str) -> Iterable[dict]
    """
    name = getattr(cls, "NAME", None)
    if not name:
        raise ValueError(f"Cannot register feed without NAME: {cls}")
    FEED_REGISTRY[name] = cls  # store the class; caller may instantiate
    return cls

# --------------------------------------------------------------------------------------
# Helpers used by parsers (kept here to avoid import cycles)
# --------------------------------------------------------------------------------------

def open_maybe_gzip(path: str, mode: str = "rt", **kw):
    """
    Open plain text or gzip files transparently for 't' (text) or 'b' (binary) mode.
    """
    if path.endswith(".gz"):
        # gzip mode must be binary; gzip can decode text if mode='rt'
        return gzip.open(path, mode, **kw)
    return open(path, mode, **kw)

def safe_ip(s: Optional[str]) -> Optional[str]:
    """
    Validate IP (v4/v6). Returns normalized string or None.
    """
    if not s:
        return None
    s = s.strip()
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s))
    except Exception:
        return None

def parse_ip_field(raw: Any) -> List[str]:
    """
    APWG-style field with a Python-ish list string like:
      "[u'199.16.173.112', u'199.16.172.157']"
    We try JSON first; if that fails, we fall back to a permissive parser.
    Returns list[str] (possibly empty).
    """
    if raw is None:
        return []
    # If it's already a python list, stringify each
    if isinstance(raw, (list, tuple)):
        return [str(x).strip() for x in raw if str(x).strip()]

    text = str(raw).strip()
    if not text:
        return []
    # Try JSON
    try:
        val = json.loads(text)
        if isinstance(val, list):
            return [str(x).strip() for x in val if str(x).strip()]
    except Exception:
        pass

    # Fall back: strip brackets and split on commas/quotes
    # Example: [u'1.2.3.4', u'5.6.7.8']
    if text.startswith("[") and text.endswith("]"):
        body = text[1:-1]
    else:
        body = text
    # split on comma but keep simple; then strip leading "u'" or "'" quotes
    out = []
    for part in body.split(","):
        p = part.strip()
        if p.startswith("u'") and p.endswith("'"):
            p = p[2:-1]
        elif p.startswith("'") and p.endswith("'"):
            p = p[1:-1]
        elif p.startswith('"') and p.endswith('"'):
            p = p[1:-1]
        p = p.strip()
        if p:
            out.append(p)
    return out

# --------------------------------------------------------------------------------------
# Base class (interface only; no inheritance required, but nice for consistency)
# --------------------------------------------------------------------------------------

class BaseFeedParser:
    NAME: str = "base"
    COUNT_DOMAINS: bool = False  # True if records contain reliable domain signal

    def iter_records(self, path: str) -> Iterable[dict]:
        """
        Yield dicts with shape:
          {"domain": <string>, "ips": [<ip strings>], "timestamp": <int|None>, "source": <feed name>}
        """
        raise NotImplementedError

# --------------------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------------------

@register_feed
class APWGCSV_IPOnly(BaseFeedParser):
    """
    APWG CSV (no header) — IP-only parser.

    Columns (by index):
      0: domain (ignored)
      1: url (ignored)
      2: timestamp (epoch; optional)
      3: ip list string, e.g. "[u'199.16.173.112', u'199.16.172.157']"

    Counts EVERY IP on the line (unique per hoster per feed).
    """
    NAME = "apwg_csv_ip"
    COUNT_DOMAINS = False

    def iter_records(self, path: str):
        with open_maybe_gzip(path, "rt", encoding="utf-8", errors="ignore") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if not row or len(row) < 4:
                    continue
                ips = {x for x in (safe_ip(i) for i in parse_ip_field(row[3])) if x}
                if not ips:
                    continue
                ts = None
                try:
                    ts = int(row[2])
                except Exception:
                    pass
                ips_list = sorted(ips)
                # Use first IP as domain placeholder (COUNT_DOMAINS=False)
                yield {"domain": ips_list[0], "ips": ips_list, "timestamp": ts, "source": self.NAME}

@register_feed
class DShieldDaily_IPOnly(BaseFeedParser):
    """
    DShield 'daily_sources' (tab-separated; '#' comments; optional header line).
    Columns:
      0: source IP (may be zero-padded)
      1: targetport
      2: protocol
      3: reports
      4: targets
      5: firstseen (HH:MM:SS, GMT)
      6: lastseen  (HH:MM:SS, GMT)
    """
    NAME = "dshield_daily"
    COUNT_DOMAINS = False

    def _normalize_ipv4(self, s: str) -> Optional[str]:
        s = (s or "").strip()
        if not s:
            return None
        parts = s.split(".")
        if len(parts) == 4:
            try:
                s = ".".join(str(int(p)) for p in parts)  # strips zero-padding
            except Exception:
                pass
        return safe_ip(s)

    def iter_records(self, path: str):
        with open_maybe_gzip(path, "rt", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s.lower().startswith("source ip"):
                    continue
                cols = s.split("\t")
                if not cols:
                    continue
                ip = self._normalize_ipv4(cols[0])
                if not ip:
                    continue
                yield {"domain": ip, "ips": [ip], "timestamp": None, "source": self.NAME}

@register_feed
class OpenPhishJSON_IPOnly(BaseFeedParser):
    """
    Accepts:
      - JSONL: one JSON object per line, or
      - JSON array: a single JSON array of objects.

    For each object, extracts IPs from:
      obj["details"][*]["ip_address"] (primary)
    Falls back to details[*]["ip"] or top-level "ip" if present.

    Emits IP-only records (COUNT_DOMAINS=False).
    """
    NAME = "phishtank_json_ip"
    COUNT_DOMAINS = False

    def _ips_from_obj(self, obj: dict) -> List[str]:
        ips = []
        det = obj.get("details")
        if isinstance(det, (list, tuple)):
            for d in det:
                if not isinstance(d, dict):
                    continue
                for key in ("ip_address", "ip"):
                    v = d.get(key)
                    if isinstance(v, str) and v.strip():
                        ips.append(v.strip())
        # fallback: top-level ip fields
        for key in ("ip_address", "ip", "ipAddress"):
            v = obj.get(key)
            if isinstance(v, str) and v.strip():
                ips.append(v.strip())
        valid = {x for x in (safe_ip(i) for i in ips) if x}
        return sorted(valid)

    def _ts_from_obj(self, obj: dict) -> Optional[int]:
        for key in ("submission_time", "verification_time", "detail_time"):
            raw = obj.get(key)
            if isinstance(raw, str) and raw.strip():
                try:
                    dt = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
                    return int(dt.timestamp())
                except Exception:
                    continue
        return None

    def iter_records(self, path: str):
        # Try JSONL streaming; if first line doesn't parse, try full file
        tried_full = False
        with open_maybe_gzip(path, "rt", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.strip()
                if not s or s == ",":
                    continue
                try:
                    obj = json.loads(s)
                except Exception:
                    tried_full = True
                    break
                ips = self._ips_from_obj(obj)
                if not ips:
                    continue
                ts = self._ts_from_obj(obj)
                yield {"domain": ips[0], "ips": ips, "timestamp": ts, "source": self.NAME}
            else:
                return  # consumed as JSONL

        if tried_full:
            with open_maybe_gzip(path, "rt", encoding="utf-8", errors="ignore") as fh2:
                text = fh2.read().strip()
                if not text:
                    return
                try:
                    obj = json.loads(text)
                except Exception:
                    # attempt to wrap lines into array
                    lines = [l.strip().rstrip(",") for l in text.splitlines() if l.strip()]
                    arr_txt = "[" + ",".join(lines) + "]"
                    try:
                        obj = json.loads(arr_txt)
                    except Exception:
                        return
                if isinstance(obj, dict):
                    obj = [obj]
                if not isinstance(obj, (list, tuple)):
                    return
                for item in obj:
                    if not isinstance(item, dict):
                        continue
                    ips = self._ips_from_obj(item)
                    if not ips:
                        continue
                    ts = self._ts_from_obj(item)
                    yield {"domain": ips[0], "ips": ips, "timestamp": ts, "source": self.NAME}

@register_feed
class ShadowserverCSV_IPOnly(BaseFeedParser):
    """
    Shadowserver CSV parser (generic, IP-only).
    Expected:
      - CSV with header, quoted fields, comma-separated.
      - 'ip' column (usually present). Fallbacks: 'source_ip','dst_ip','src_ip','target','address'.
      - Optional 'timestamp' column (ISO string).
    """
    NAME = "shadowserver_csv_ip"
    COUNT_DOMAINS = False

    _IP_COLS = ("ip", "source_ip", "src_ip", "dst_ip", "target", "address")
    _TS_COLS = ("timestamp", "time", "first_seen", "firstseen")

    def _pick_col(self, header: List[str], candidates: Tuple[str, ...]) -> Optional[str]:
        lcmap = {h.lower(): h for h in header}
        for c in candidates:
            if c in lcmap:
                return lcmap[c]
        return None

    def _parse_ts(self, row: dict, ts_col: Optional[str]) -> Optional[int]:
        if not ts_col:
            return None
        raw = row.get(ts_col)
        if not raw:
            return None
        s = str(raw).strip()
        if not s:
            return None
        try:
            s2 = s.replace("Z", "+00:00").replace(" ", "T")
            dt = datetime.fromisoformat(s2)
            if dt.tzinfo is None:
                from datetime import timezone
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except Exception:
            return None

    def iter_records(self, path: str):
        with open_maybe_gzip(path, "rt", encoding="utf-8", errors="ignore") as fh:
            rdr = csv.DictReader(fh, delimiter=",", quotechar='"')
            header = [h.strip() for h in (rdr.fieldnames or [])]
            if not header:
                return
            ip_col = self._pick_col(header, self._IP_COLS)
            if not ip_col:
                return
            ts_col = self._pick_col(header, self._TS_COLS)

            for row in rdr:
                if not row:
                    continue
                ip = safe_ip(str(row.get(ip_col, "")).strip())
                if not ip:
                    continue
                ts = self._parse_ts(row, ts_col)
                yield {"domain": ip, "ips": [ip], "timestamp": ts, "source": self.NAME}

@register_feed
class SpamhausEXBL_JSONL_IPOnly(BaseFeedParser):
    """
    Spamhaus EXBL v4 daily JSON/JSONL.
    Extract IPs from 'ipaddress' (primary) / 'srcip' (fallback).
    """
    NAME = "spamhaus_exbl_v4"
    COUNT_DOMAINS = False

    def _ips_from_obj(self, obj: dict) -> list:
        candidates = []
        for key in ("ipaddress", "srcip"):
            v = obj.get(key)
            if isinstance(v, str) and v.strip():
                candidates.append(v.strip())
        return sorted({x for x in (safe_ip(i) for i in candidates) if x})

    def _ts_from_obj(self, obj: dict) -> Optional[int]:
        for key in ("seen", "listed", "firstseen"):
            v = obj.get(key)
            if isinstance(v, int):
                return v
            if isinstance(v, str):
                try:
                    return int(v.strip())
                except Exception:
                    pass
        return None

    def iter_records(self, path: str):
        with open_maybe_gzip(path, "rt", encoding="utf-8", errors="ignore") as fh:
            # Try full JSON (array/dict)
            pos = fh.tell()
            first = ""
            for line in fh:
                if line.strip():
                    first = line.lstrip()
                    break
            fh.seek(pos)

            if first.startswith("[") or first.startswith("{"):
                try:
                    data = json.load(fh)
                except Exception:
                    data = None
                if data is not None:
                    items = []
                    if isinstance(data, list):
                        items = data
                    elif isinstance(data, dict):
                        # dict-of-lists
                        for v in data.values():
                            if isinstance(v, list):
                                items.extend(v)
                            elif isinstance(v, dict):
                                items.append(v)
                    for obj in items:
                        if not isinstance(obj, dict) or obj.get("type") == "metadata":
                            continue
                        ips = self._ips_from_obj(obj)
                        if not ips:
                            continue
                        ts = self._ts_from_obj(obj)
                        yield {"domain": ips[0], "ips": ips, "timestamp": ts, "source": self.NAME}
                    return

            # Otherwise JSONL (one object per line)
            for line in fh:
                s = line.strip()
                if not s or s in ("[", "]", ","):
                    continue
                try:
                    obj = json.loads(s.rstrip(","))
                except Exception:
                    continue
                if not isinstance(obj, dict) or obj.get("type") == "metadata":
                    continue
                ips = self._ips_from_obj(obj)
                if not ips:
                    continue
                ts = self._ts_from_obj(obj)
                yield {"domain": ips[0], "ips": ips, "timestamp": ts, "source": self.NAME}

@register_feed
class BlocklistDe_IPOnly(BaseFeedParser):
    """
    blocklist.de (or similar) plain text IP list.
    Each line = one IP address (ignores blank/comment lines).
    """
    NAME = "blocklist_de"
    COUNT_DOMAINS = False

    def _normalize_ipv4(self, s: str) -> Optional[str]:
        s = (s or "").strip()
        if not s:
            return None
        if ":" in s:  # IPv6
            return safe_ip(s)
        parts = s.split(".")
        if len(parts) == 4:
            try:
                s = ".".join(str(int(p)) for p in parts)  # remove leading zeros
            except Exception:
                pass
        return safe_ip(s)

    def iter_records(self, path: str):
        with open_maybe_gzip(path, "rt", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#") or s.startswith(";"):
                    continue
                ip = self._normalize_ipv4(s)
                if not ip:
                    continue
                yield {"domain": ip, "ips": [ip], "timestamp": None, "source": self.NAME}

@register_feed
class ThreatFoxJSON_IPOnly(BaseFeedParser):
    """
    abuse.ch ThreatFox / MalwareBazaar JSON export (dict keyed by ID → list of IOCs).
    Extract IPs from ioc_value (drops ports).
    """
    NAME = "threatfox_json_ip"
    COUNT_DOMAINS = False

    def _ips_from_obj(self, obj: dict) -> list:
        candidates = []
        for key in ("ioc_value", "value", "indicator"):
            v = obj.get(key)
            if not isinstance(v, str):
                continue
            val = v.strip()
            if ":" in val:  # strip ports if present
                val = val.split(":", 1)[0]
            if val:
                candidates.append(val)
        return sorted({x for x in (safe_ip(i) for i in candidates) if x})

    def _ts_from_obj(self, obj: dict) -> Optional[int]:
        for key in ("first_seen_utc", "last_seen_utc"):
            v = obj.get(key)
            if isinstance(v, str) and v.strip():
                try:
                    dt = datetime.fromisoformat(v.strip().replace(" ", "T"))
                    return int(dt.timestamp())
                except Exception:
                    pass
        return None

    def iter_records(self, path: str):
        with open_maybe_gzip(path, "rt", encoding="utf-8", errors="ignore") as fh:
            text = fh.read().strip()
            if not text:
                return
            try:
                data = json.loads(text)
            except Exception:
                return
            # Some dumps are a list instead of dict
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = []
                for v in data.values():
                    if isinstance(v, list):
                        items.extend(v)
                    elif isinstance(v, dict):
                        items.append(v)
                    # skip scalars
            else:
                return

            for obj in items:
                if not isinstance(obj, dict):
                    continue
                ips = self._ips_from_obj(obj)
                if not ips:
                    continue
                ts = self._ts_from_obj(obj)
                yield {"domain": ips[0], "ips": ips, "timestamp": ts, "source": self.NAME}

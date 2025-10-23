import lmdb
from collections import defaultdict
import ipaddress

class Store:
    def __init__(self, path, map_size_gb=64):
        self.env = lmdb.open(
            path,
            map_size=map_size_gb * 1024 ** 3,
            subdir=True,
            max_dbs=1,
            readonly=False,
            lock=True,
            readahead=False,
            meminit=False
        )

    def close(self):
        self.env.close()


class Processor:
    def __init__(self, hosters, store, feed_policy):
        self.hosters = hosters  # dict[str, list[str]]
        self.store = store
        self.feed_policy = feed_policy

        self.seen = defaultdict(lambda: defaultdict(set))   # hoster → feed → set(ip or domain)
        self.shared = defaultdict(set)                      # hoster → set(shared ips)

    def _find_owner(self, ip: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return "UNKNOWN"
        for org, prefixes in self.hosters.items():
            for prefix in prefixes:
                try:
                    if ip_obj in ipaddress.ip_network(prefix):
                        return org
                except Exception:
                    continue
        return "UNKNOWN"

    def ingest_record(self, record, txn):
        """
        record: dict with at least 'feed', 'ip', and optionally 'domain'
        """
        ip = record.get("ip")
        domain = record.get("domain")
        feed = record.get("feed")
        if not ip or not feed:
            return

        owner = self._find_owner(ip)
        if owner == "UNKNOWN":
            return

        if self.feed_policy.get(feed, True):  # domain counting enabled
            if domain:
                self.seen[owner][f"{feed}_domains"].add(domain)
        self.seen[owner][f"{feed}_ips"].add(ip)

    def finalize_shared(self):
        # Simple placeholder – extend if needed
        pass

    def results(self, hoster_list, feeds_to_report, feed_policy):
        rows = []
        for hoster in hoster_list:
            row = [hoster]
            for feed in feeds_to_report:
                if feed_policy.get(feed, True):
                    d_count = len(self.seen[hoster].get(f"{feed}_domains", set()))
                    i_count = len(self.seen[hoster].get(f"{feed}_ips", set()))
                    row += [d_count, i_count]
                else:
                    i_count = len(self.seen[hoster].get(f"{feed}_ips", set()))
                    row += [i_count]
            # Placeholder columns
            row += [
                0,  # domaincount_seen
                len(set().union(*[self.seen[hoster][k] for k in self.seen[hoster] if k.endswith("_ips")])),
                0,  # ipcount_shared
                0   # domaincount_shared
            ]
            rows.append(row)
        return rows

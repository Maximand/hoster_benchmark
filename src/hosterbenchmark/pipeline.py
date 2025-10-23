from hosterbenchmark.domains.extract import extract_dnsdb
from hosterbenchmark.domains.enrich import enrich_pairs
from hosterbenchmark.counts.unique_slds import count_unique_slds
from hosterbenchmark.counts.capacity import compute_capacity
from hosterbenchmark.feeds.runner import ingest_and_export
from hosterbenchmark.merge.join_capacity import merge_counts

def run_pipeline(config_path: str):
    print("[*] Starting full HosterBenchmark pipeline")
    extract_dnsdb(config_path)
    enrich_pairs(config_path)
    count_unique_slds(config_path)
    compute_capacity(config_path)
    ingest_and_export(config_path)
    merge_counts(config_path)
    print("[✓] Pipeline completed.")

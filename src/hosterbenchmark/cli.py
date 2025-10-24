import typer
from hosterbenchmark.pipeline import run_pipeline
from hosterbenchmark.domains.extract import extract_dnsdb
from hosterbenchmark.domains.enrich import enrich_pairs
from hosterbenchmark.counts.unique_slds import count_unique_slds
from hosterbenchmark.counts.capacity import compute_capacity
from hosterbenchmark.feeds.runner import ingest_and_export
from hosterbenchmark.merge.join_capacity import merge_counts

app = typer.Typer(help="HosterBenchmark pipeline")

@app.command()
def run(config: str = "config/pipeline.yaml"):
    """Run full pipeline from YAML config."""
    run_pipeline(config)

@app.command()
def extract(config: str = "config/pipeline.yaml"):
    extract_dnsdb(config)

@app.command()
def enrich(config: str = "config/pipeline.yaml"):
    enrich_pairs(config)

@app.command()
def slds(config: str = "config/pipeline.yaml"):
    count_unique_slds(config)

@app.command()
def capacity(config: str = "config/pipeline.yaml"):
    compute_capacity(config)

@app.command()
def ingest(config: str = "config/pipeline.yaml"):
    ingest_and_export(config)

@app.command()
def merge(config: str = "config/pipeline.yaml"):
    merge_counts(config)

# HosterBenchmark: Modular Benchmarking Pipeline for Hosting Provider Analysis

**HosterBenchmark** is a modular, reproducible benchmarking pipeline for measuring security-related activity across hosting providers.  
It extracts, enriches, counts, and correlates signals from large-scale datasets such as DNS records and abuse feeds to generate per-provider metrics on exposure, capacity, and abuse.

---

## ⚙️Overview

HosterBenchmark runs as a **six-step pipeline**, each modular and re-runnable:

| Step | Module | Description |
|------|---------|-------------|
| **1** | `domains.extract` | Extracts second-level domains (2LDs) and IPs from large DNSDB-style JSONL datasets. |
| **2** | `domains.enrich` | Enriches extracted records with their corresponding hosting provider using CIDR maps. |
| **3** | `counts.unique_slds` | Counts unique second-level domains per hosting provider and attaches their CIDRs. |
| **4** | `counts.capacity` | Computes IP-space capacity and address statistics from CIDR lists. |
| **5** | `feeds.runner` | Ingests IP-based abuse feeds and counts how many hits fall into each provider’s prefixes. |
| **6** | `merge.join_capacity` | Merges exposure, capacity, and abuse statistics into a single benchmarking table. |

The pipeline can be executed end-to-end or per step, driven by a simple YAML configuration file.

---

## Repository structure

```
hoster_benchmark/
├── config/
│   ├── pipeline.yaml        # main pipeline configuration
│   ├── feeds.yaml           # feed sources and paths
│   └── hosters.txt          # CIDR map for hosting providers
├── data/
│   ├── dnsdb_dummy/         # example DNSDB-like input files
│   ├── feeds/               # example abuse feeds
│   ├── output/              # generated output tables
│   └── work/                # intermediate LMDB/temp directories
├── src/hosterbenchmark/
│   ├── cli.py               # Typer CLI entrypoint
│   ├── pipeline.py          # orchestrator (runs all steps)
│   ├── domains/
│   │   ├── extract.py
│   │   └── enrich.py
│   ├── counts/
│   │   ├── unique_slds.py
│   │   └── capacity.py
│   ├── feeds/
│   │   ├── runner.py
│   │   ├── store.py
│   │   └── parsers.py
│   └── merge/
│       └── join_capacity.py
└── README.md
```

---

## 🔧 Installation

```bash
git clone https://github.com/Maximand/hoster_benchmark.git
cd hoster_benchmark
pip install -e .
```

This installs all dependencies (see `pyproject.toml`) and makes the CLI available via:

```bash
python3 -m hosterbenchmark --help
```

---

## 🚀 Running the full pipeline

### 1. Configure your run

Edit `config/pipeline.yaml` to define:

- Input DNSDB data glob
- CIDR map (hosting provider → prefix list)
- Feed configuration (`config/feeds.yaml`)
- Output destinations

Example:

```yaml
paths:
  dnsdb_glob: "data/dnsdb_dummy/*.json.gz"
  step1_out_dir: "data/work/step1"
  step2_out_dir: "data/work/step2"
  tmpdir_step3: "data/work/tmp3"
  lmdb_dir: "data/work/lmdb"
  cidr_map: "config/hosters.txt"

feeds_file: "config/feeds.yaml"
hosters_file: "config/hosters.txt"

outputs:
  orgs_over_threshold: "data/output/orgs.csv"
  capacity_csv: "data/output/capacity.csv"
  hoster_counts_csv: "data/output/feeds.csv"
  merged_csv: "data/output/merged.csv"

params:
  threshold_sld_count: 1
  commit_every: 10
  lmdb_map_gb: 1
```

### 2. Run

```bash
python3 -m hosterbenchmark run --config config/pipeline.yaml
```

---

## Step-by-step details

### Step 1 — Domain Extraction
Extracts second-level domains (2LDs) and IPs from large DNSDB-style JSONL datasets.

### Step 2 — Enrichment
Maps extracted IPs to hosting providers via CIDR maps.

### Step 3 — Unique SLD Counting
Counts unique domains per hosting provider and exports CSV.

### Step 4 — Capacity Computation
Computes total address capacity and domain density.

### Step 5 — Feed Ingestion
Counts IP-only abuse feed hits per provider using LMDB-backed storage.

### Step 6 — Merge
Merges exposure, capacity, and abuse metrics into a unified benchmark dataset.

---

## Configuration summary

| Key | Description |
|-----|-------------|
| `paths.dnsdb_glob` | Input DNSDB files |
| `paths.cidr_map` | Hosting provider → CIDR mapping |
| `feeds_file` | Feed definition YAML |
| `outputs.*` | Output file paths |
| `params.threshold_sld_count` | Minimum SLDs per org |
| `params.commit_every` | LMDB commit frequency |

---

## Dummy Dataset

The repository includes example data under `data/`:

- 50 hosters (`config/hosters.txt`)
- 100 DNSDB records (`data/dnsdb_dummy/sample.json.gz`)
- 20 feed hits (`data/feeds/dummy_feed.csv`)

Run:

```bash
python3 -m hosterbenchmark run --config config/pipeline.yaml
```

---

## Individual steps

```bash
python3 -m hosterbenchmark extract --config config/pipeline.yaml
python3 -m hosterbenchmark enrich --config config/pipeline.yaml
python3 -m hosterbenchmark slds --config config/pipeline.yaml
python3 -m hosterbenchmark capacity --config config/pipeline.yaml
python3 -m hosterbenchmark ingest --config config/pipeline.yaml
python3 -m hosterbenchmark merge --config config/pipeline.yaml
```

---

## Outputs

| File | Description |
|------|-------------|
| `data/output/orgs.csv` | Domains per hoster |
| `data/output/capacity.csv` | IP capacity metrics |
| `data/output/feeds.csv` | Abuse feed hit counts |
| `data/output/merged.csv` | Combined benchmark dataset |

---

## Extending the Framework

Add new feed parsers by creating a class in `feeds/parsers.py`:

```python
@register_feed
class ShadowserverExample(BaseFeedParser):
    NAME = "shadowserver_example"
    COUNT_DOMAINS = False

    def iter_records(self, path: str):
        with open(path) as fh:
            for line in fh:
                ip = line.strip().split(",")[0]
                yield FeedRecord(domain=None, ips=[ip], source=self.NAME)
```

Then reference it in `config/feeds.yaml`:

```yaml
feeds:
  - name: shadowserver_example
    path: data/feeds/shadowserver/*.csv
```

---

## License

MIT License — see `LICENSE`.

---

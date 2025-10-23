# 🧭 HosterBenchmark: Modular Benchmarking Pipeline for Hosting Provider Analysis

**HosterBenchmark** is a modular, reproducible benchmarking pipeline for measuring security-related activity across hosting providers.  
It extracts, enriches, counts, and correlates signals from large-scale datasets such as DNS records and abuse feeds to generate per-provider metrics on exposure, capacity, and abuse.

---

## ⚙️ Overview

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

## 🧩 Repository structure

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
git clone https://github.com/yourname/hoster_benchmark.git
cd hoster_benchmark
pip install -e .
```

This installs all dependencies (see `pyproject.toml`) and makes the CLI available via:

```bash
python3 -m hosterbenchmark --help
```

---

## 🗺️ Hosters file format (`config/hosters.txt`)

HosterBenchmark expects a **pipe-delimited** file describing hosting providers and their IP address ranges.  
This file is typically derived from **MaxMind’s GeoLite2 ASN or ISP database**, enriched with your own mappings.

### ✅ Example (with header)

```
Organization|Ranges|Size|Country_hist
Zeimudo Networks Ltd.|['1.3.3.0/24', '103.1.72.0/22']|1280|{'CN': 256, 'UA': 1024}
ExampleHoster B.V.|["192.0.2.0/24","198.51.100.0/24"]|512|{'NL': 512}
FastNet AB|203.0.113.0/24, 203.0.114.0/23|768|{'SE': 768}
```

### 🧩 Supported input variations

The parser accepts several common formats for the `Ranges` field:

| Format | Example | Accepted |
|---------|----------|----------|
| Python list | `['1.3.3.0/24', '103.1.72.0/22']` | ✅ |
| JSON list | `["1.3.3.0/24","103.1.72.0/22"]` | ✅ |
| Comma-separated | `1.3.3.0/24, 103.1.72.0/22` | ✅ |
| Pipe-separated | `1.3.3.0/24 | 103.1.72.0/22` | ✅ |

Additional fields (like `Size` or `Country_hist`) are **optional** and automatically ignored if not needed,  
but can later be reintroduced in analytics or merged into final outputs if you pass `return_meta=True` in `load_hosters()`.

### 📘 Minimal version (no header)

```
Zeimudo Networks Ltd.|1.3.3.0/24,103.1.72.0/22
ExampleHoster B.V.|192.0.2.0/24,198.51.100.0/24
FastNet AB|203.0.113.0/24
```

Both forms (with or without header) are accepted.

### 🧠 How it’s used internally

- **Step 2 (Enrichment)** and **Step 5 (Abuse Feed Ingestion)** both load this file via:

```python
from hosterbenchmark.feeds.parsers import load_hosters
hosters = load_hosters("config/hosters.txt")
```

This returns:
```python
{
  "Zeimudo Networks Ltd.": ["1.3.3.0/24", "103.1.72.0/22"],
  "ExampleHoster B.V.": ["192.0.2.0/24", "198.51.100.0/24"],
  ...
}
```

If you also want metadata (e.g., `Size`, `Country_hist`):

```python
hosters, hoster_meta = load_hosters("config/hosters.txt", return_meta=True)
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

## 📊 Outputs

| File | Description |
|------|-------------|
| `data/output/orgs.csv` | Domains per hoster |
| `data/output/capacity.csv` | IP capacity metrics |
| `data/output/feeds.csv` | Abuse feed hit counts |
| `data/output/merged.csv` | Combined benchmark dataset |

---

## 🧠 Extending the Framework

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

## 🧾 License

MIT License — see `LICENSE`.

---

## 👤 Author

Developed by **Max van der Horst**  
Part of ongoing research on hosting provider abuse governance and vulnerability disclosure under the TU Delft / EGOS project.

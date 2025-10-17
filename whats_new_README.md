# SymbolicHunter

_Comprehensive symbolic execution & triage with angr_

SymbolicHunter automates vulnerability discovery, taint-to-sink tracing, and “path-to-interesting-API” hunting across single binaries or entire directories (Linux, macOS, and Windows PE). It produces structured JSON, 
an HTML triage report, a per-path JSONL log, and a signature bundle (YARA + IOC + simple rules). An optional evaluator generates Pandas tables and Matplotlib charts for reviewer-friendly metrics.

Evaluation metrics: tools/eval_metrics.py aggregates all sample outputs into CSV + charts (bar, histogram, line).

---

## Quick start

```bash
# 1) Create and activate a venv (recommended)
python3 -m venv .venv && source .venv/bin/activate

# 2) Install dependencies
pip install -r requirements.txt
# If you haven’t yet, add the evaluator deps:
pip install pandas matplotlib

# Analyze everything recursively
python3 symbolic_hunter.py ~/lab/evasive-angr/samples --recursive -o output/dir_reports/

# Generate metrics and plots
python3 tools/eval_metrics.py --outputs output/dir_reports --save

# Inspect the table
column -s, -t < output/dir_reports/eval_reports/metrics.csv | less -S




Note: Source files like *.c are not binaries; they’ll be skipped unless you pre-compile them. Some non-ELF/Mach-O/PE blobs may load via angr’s blob backend; otherwise they’re reported as no loader backend.


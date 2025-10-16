#!/usr/bin/env python3
"""
Evaluation metrics & reviewer plots for SymbolicHunter outputs.

Usage:
  python3 tools/eval_metrics.py --outputs output/dir_reports --save
"""

import argparse
import json
from pathlib import Path
from typing import Dict, Any, List, Tuple

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

API_FAMILY_MAP = {
    "persistence": ["RegSetValue", "CreateService", "schtasks", "LaunchAgents", "crontab"],
    "crypto": ["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt", "AES_", "DES_"],
    "network": ["connect", "send", "recv", "socket", "InternetOpen", "WinHttp", "curl_easy_"],
    "file": ["CreateFile", "WriteFile", "fopen", "fwrite", "open", "read", "write"],
    "process": ["CreateProcess", "WinExec", "ShellExecute", "exec", "popen"],
    "library": ["LoadLibrary", "GetProcAddress", "dlopen", "dlsym"],
    "string": ["strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf", "memcpy"],
}

def _collect_results_jsons(root: Path) -> List[Path]:
    return [p for p in root.rglob("results.json") if p.is_file()]

def _infer_family(row: Dict[str, Any]) -> str:
    bn = Path(row.get("binary", "")).name
    return Path(bn).stem if bn else "unknown"

def _suspicious_api_coverage(dangerous_functions: List[Dict[str, Any]]) -> float:
    target_fams = {"persistence", "crypto", "network"}
    found = set()
    names = [f.get("name", "") for f in dangerous_functions if isinstance(f, dict)]
    for fam, patterns in API_FAMILY_MAP.items():
        for pat in patterns:
            if any(pat.lower() in (n or "").lower() for n in names):
                found.add(fam); break
    return len(found.intersection(target_fams)) / len(target_fams) if target_fams else float("nan")

def _constraints_avg(constraints_sample: List[Dict[str, Any]]) -> float:
    vals = [c.get("num_constraints") for c in (constraints_sample or []) if isinstance(c.get("num_constraints"), (int,float))]
    return float(sum(vals)/len(vals)) if vals else float("nan")

def _load_paths_jsonl(results_path: Path) -> Tuple[int, int, float]:
    """
    Returns: (records, unique_hashes, avg_bb_count) from paths.jsonl if present.
    """
    p = results_path.parent / "paths.jsonl"
    if not p.exists():
        return (0, 0, float("nan"))
    uniq = set(); counts = []; recs = 0
    with open(p, "r") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                obj = json.loads(line)
                recs += 1
                h = obj.get("bb_hash")
                if h: uniq.add(h)
                c = obj.get("bb_count")
                if isinstance(c, int): counts.append(c)
            except Exception:
                pass
    avg = (sum(counts)/len(counts)) if counts else float("nan")
    return (recs, len(uniq), avg)

def _make_eval_row(jpath: Path) -> Dict[str, Any]:
    j = json.loads(jpath.read_text(encoding="utf-8", errors="ignore"))
    stats = j.get("statistics", {}) or {}
    vulns = j.get("vulnerabilities", {}) or {}
    dang = j.get("dangerous_functions", []) or []
    taint = j.get("taint_analysis", {}) or {}

    P = int(stats.get("paths_explored", 0))
    T = float(stats.get("time_elapsed", 0.0))
    cov = float(stats.get("code_coverage", 0.0))

    # UPR / L_avg from paths.jsonl
    recs, uniq, avg_bb = _load_paths_jsonl(jpath)
    UPR = (uniq / P) if P else float("nan")
    L_avg = avg_bb

    row = {
        "results_path": str(jpath),
        "binary": j.get("binary", ""),
        "family": _infer_family(j),
        "paths_explored_P": P,
        "time_elapsed_T_sec": T,
        "path_discovery_rate_PDR": (P / T) if (T and T > 0) else float("nan"),
        "code_coverage_pct": cov,
        "payload_found": bool(j.get("payload_found", False)),
        "suspicious_api_coverage_SAC": _suspicious_api_coverage(dang if isinstance(dang, list) else []),
        "constraints_avg_C_avg": _constraints_avg(j.get("constraints_sample", [])),
        "solved_constraint_ratio_SCR": float("nan"),
        "unique_path_ratio_UPR": UPR,
        "avg_path_length_L_avg": L_avg,
        "trigger_input_success_rate_TISR": float("nan"),
        "memory_dump_entropy_E_mem": float("nan"),
        "explanation_faithfulness_EF": float("nan"),
        "analyst_triage_time_ATT_sec": float("nan"),
        "vuln_total_count": sum(len(v) for v in vulns.values()),
        "tainted_sinks_count": int(taint.get("sinks_found", 0)),
        "data_flows_count": len(taint.get("data_flows", [])),
        "paths_records_logged": recs,
        "paths_unique_bb_hashes": uniq,
    }
    return row

def _heatmap_data(api_counts_by_family: Dict[str, Dict[str, int]]) -> pd.DataFrame:
    fams = sorted(api_counts_by_family.keys())
    cols = sorted(set(c for v in api_counts_by_family.values() for c in v.keys()))
    data = []
    for fam in fams:
        data.append([api_counts_by_family[fam].get(c, 0) for c in cols])
    return pd.DataFrame(data, index=fams, columns=cols)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outputs", required=True, help="Directory containing per-sample results.json (recursive).")
    ap.add_argument("--save", action="store_true", help="Write CSV and PNGs to eval_reports/.")
    args = ap.parse_args()

    root = Path(args.outputs).expanduser().resolve()
    rjs = _collect_results_jsons(root)
    if not rjs:
        print(f"No results.json under {root}")
        return

    rows = []
    api_counts_by_family: Dict[str, Dict[str, int]] = {}
    for rj in rjs:
        row = _make_eval_row(rj)
        rows.append(row)
        # heatmap (bucketize dangerous functions into API families)
        try:
            j = json.loads(rj.read_text(encoding="utf-8", errors="ignore"))
            dang = j.get("dangerous_functions", []) or []
            fam = row["family"]
            api_counts_by_family.setdefault(fam, {})
            for bucket, pats in API_FAMILY_MAP.items():
                if any(any(p.lower() in (df.get("name","").lower()) for p in pats) for df in dang):
                    api_counts_by_family[fam][bucket] = api_counts_by_family[fam].get(bucket, 0) + 1
        except Exception:
            pass

    import pandas as pd
    df = pd.DataFrame(rows).sort_values(["family","paths_explored_P"], ascending=[True, False])
    print("\n=== Metrics preview (top 12) ===")
    try:
        print(df.head(12).to_string(index=False))
    except Exception:
        print(df.head(12))

    if args.save:
        report_dir = root / "eval_reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        csv_path = report_dir / "metrics.csv"
        df.to_csv(csv_path, index=False)
        print(f"[+] Wrote CSV: {csv_path}")

        # Bar: Paths per sample
        try:
            plt.figure(); order = df.sort_values("paths_explored_P", ascending=False)
            plt.bar(range(len(order)), order["paths_explored_P"])
            plt.title("Path count per sample"); plt.xlabel("Sample index"); plt.ylabel("Paths (P)")
            plt.tight_layout(); p1 = report_dir / "bar_paths_per_sample.png"; plt.savefig(p1, dpi=160); plt.close(); print(f"[+] {p1}")
        except Exception as e: print("Plot error:", e)

        # Line: PDR
        try:
            plt.figure(); order = df.sort_values("path_discovery_rate_PDR", ascending=False)
            plt.plot(range(len(order)), order["path_discovery_rate_PDR"])
            plt.title("Path discovery rate (paths/sec)"); plt.xlabel("Sample index"); plt.ylabel("PDR")
            plt.tight_layout(); p2 = report_dir / "line_pdr.png"; plt.savefig(p2, dpi=160); plt.close(); print(f"[+] {p2}")
        except Exception as e: print("Plot error:", e)

        # Histogram: L_avg (BBs per path)
        try:
            plt.figure(); series = df["avg_path_length_L_avg"].dropna()
            plt.hist(series, bins=20); plt.title("Histogram: path length (basic blocks)")
            plt.xlabel("BBs per path"); plt.ylabel("Frequency")
            plt.tight_layout(); p3 = report_dir / "hist_path_len.png"; plt.savefig(p3, dpi=160); plt.close(); print(f"[+] {p3}")
        except Exception as e: print("Plot error:", e)

        # Heatmap: API family frequencies
        try:
            hm = _heatmap_data(api_counts_by_family)
            if not hm.empty:
                plt.figure(); im = plt.imshow(hm.values, aspect="auto")
                plt.title("API family frequencies by sample family")
                plt.xlabel("API family bucket"); plt.ylabel("Sample family")
                plt.xticks(range(hm.shape[1]), hm.columns, rotation=45, ha="right")
                plt.yticks(range(hm.shape[0]), hm.index); plt.colorbar(im, fraction=0.046, pad=0.04)
                plt.tight_layout(); p4 = report_dir / "heatmap_api_frequencies.png"; plt.savefig(p4, dpi=160); plt.close(); print(f"[+] {p4}")
            else:
                print("[i] Heatmap skipped (no data).")
        except Exception as e: print("Plot error:", e)

        # Scatter: Coverage vs PDR
        try:
            plt.figure()
            x = df["code_coverage_pct"].fillna(0); y = df["path_discovery_rate_PDR"].fillna(0)
            plt.scatter(x, y); plt.title("Coverage vs PDR")
            plt.xlabel("Code coverage (%)"); plt.ylabel("PDR (paths/sec)")
            plt.tight_layout(); p5 = report_dir / "scatter_coverage_vs_pdr.png"; plt.savefig(p5, dpi=160); plt.close(); print(f"[+] {p5}")
        except Exception as e: print("Plot error:", e)

    # Console summary
    n = len(df)
    print(f"\n=== Summary over {n} samples ===")
    print(f"Mean paths explored (P): {df['paths_explored_P'].mean():.2f}")
    print(f"Mean PDR (paths/sec): {df['path_discovery_rate_PDR'].mean():.4f}")
    print(f"Mean coverage (%): {df['code_coverage_pct'].mean():.2f}")
    print(f"Mean UPR: {df['unique_path_ratio_UPR'].mean():.3f}")
    print(f"Mean L_avg (BBs): {df['avg_path_length_L_avg'].mean():.2f}")

if __name__ == "__main__":
    main()

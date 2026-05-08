"""Cost / latency analysis for paper Section V (reviewer response).

Reads existing artifacts only --- no new GPU jobs --- and produces:
1. Per-(model, dataset, task, level) input-token statistics from the same
   prompt template the production pipeline uses.
2. Per-(model, task) wall-clock latency regression on input tokens, derived
   from the scheduler logs and used to project per-level latency at the
   level-median token length.
3. A cost rollup translating tokens -> $ for GPT-4.1-mini and seconds -> $
   for self-hosted models on L40S/A100.
4. A LaTeX-ready table fragment for the appendix and a CSV manifest.

Usage:
    python experiments/analysis/cost_latency_analysis.py all
    # or run a single phase
    python experiments/analysis/cost_latency_analysis.py tokens
    python experiments/analysis/cost_latency_analysis.py latency
    python experiments/analysis/cost_latency_analysis.py costs
    python experiments/analysis/cost_latency_analysis.py paper-table

CPU-only: only tokenizers are loaded, never model weights.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import hashlib
import json
import os
import re
import sqlite3
import sys
import warnings
from collections import defaultdict
from pathlib import Path
from statistics import mean, median
from typing import Iterable, Optional

# Workaround for transformers 5.5 + torch 2.6 flex_attention import bug.
import torch.nn.attention.flex_attention as _fa  # noqa: E402

if not hasattr(_fa, "AuxRequest"):
    _fa.AuxRequest = None  # type: ignore[attr-defined]

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS = PROJECT_ROOT / "results" / "output"
LOGS_DIR = RESULTS / "scheduler" / "logs"
OUT_DIR = RESULTS / "cost_latency"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Pricing snapshot (retrieved 2026-05-06 from public OpenAI / RunPod pages).
# Cite this date in the paper.
PRICING = {
    "gpt-4.1-mini": {
        "input_per_1m_usd": 0.40,    # USD per 1M input tokens
        "output_per_1m_usd": 1.60,   # USD per 1M output tokens
        "source": "OpenAI public pricing, retrieved 2026-05-06",
    },
    "L40S": {
        "usd_per_hour": 0.86,        # RunPod community L40S spot, 2026-05-06
        "source": "RunPod community L40S spot, 2026-05-06",
    },
    "A100_80G": {
        "usd_per_hour": 1.89,        # RunPod community A100 80G spot, 2026-05-06
        "source": "RunPod community A100 80G spot, 2026-05-06",
    },
}

# Open-source models we care about. Production deployment GPU is L40S except
# Qwen3-Coder-30B which needs A100 80G.
OSS_MODELS: dict[str, dict] = {
    "llama":        {"hf_id": "meta-llama/Llama-3.1-8B-Instruct",       "deploy_gpu": "L40S"},
    "mistral":      {"hf_id": "mistralai/Mistral-7B-Instruct-v0.3",      "deploy_gpu": "L40S"},
    "deepseek":     {"hf_id": "deepseek-ai/DeepSeek-R1-Distill-Llama-8B","deploy_gpu": "L40S"},
    "starcoder":    {"hf_id": "bigcode/starcoder2-7b",                   "deploy_gpu": "L40S"},
    "codellama":    {"hf_id": "codellama/CodeLlama-7b-hf",               "deploy_gpu": "L40S"},
    "qwen3_coder":  {"hf_id": "Qwen/Qwen3-Coder-30B-A3B-Instruct",       "deploy_gpu": "A100_80G"},
}

# Database file naming convention in repo.
DB_FILENAME = {
    "llama":       "database_llama_database.sqlite",
    "mistral":     "database_mistral_database.sqlite",
    "deepseek":    "database_deepseek_database.sqlite",
    "qwen3_coder": "database_qwen3_coder_database.sqlite",
    "starcoder":   "database_starcoder_database.sqlite",
    "codellama":   "database_codellama_database.sqlite",
    "gpt-4.1-mini": "database_gpt-4.1_database.sqlite",
}

# Vendor-published p50 latency for gpt-4.1-mini at our context lengths.
# Source: OpenAI status page latency dashboard, p50 over 7 days, retrieved 2026-05-06.
GPT41_MINI_VENDOR_LATENCY_S = {
    "L1": 0.55,   # ~500-input-token prompts, p50 wall-clock incl. network
    "L2": 0.95,   # ~1500-input-token prompts
    "L3": 2.10,   # ~5000-input-token prompts
    "source": "Vendor-quoted (OpenAI status page p50, 2026-05-06).",
}

# Production prompt template (verbatim from src/models/llm_manager.py:1428).
PROMPT_VULN = """Check if the following C code block is vulnerable.
Respond with ONLY one of these options:
- '1' if the code is vulnerable
- '0' if the code is not vulnerable
- 'not sure' if you are not sure if it is vulnerable or not

Do not include any explanation or additional text.

Code block:
{code_block}

Response:"""

# Production CVE/CWE prompt template (verbatim from llm_manager.py:1565).
PROMPT_CVE_CWE = """Check if the following C code block is vulnerable to the specific CVE ({cve}) and CWE(s) ({cwe_list}).
Respond with ONLY one of these options:
- '1' if the code is vulnerable
- '0' if the code is not vulnerable
- 'not sure' if you are not sure if it is vulnerable or not

Do not include any explanation or additional text.

Code block:
{code_block}

Response:"""

TASKS = (
    "is_vulnerable_vuln",
    "is_vulnerable_patch",
    "is_vulnerable_vuln_cve_cwe",
    "is_vulnerable_patch_cve_cwe",
)

ABSTRACTION_LEVELS = ("L1", "L2", "L3")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def categorise(num_files: int, num_funcs: int) -> str:
    """Mirror experiments/analysis/evaluate_abstraction.py:221-230."""
    if num_files == 1 and num_funcs <= 1:
        return "L1"
    if num_files == 1 and num_funcs > 1:
        return "L2"
    return "L3"


def normalise_cwe_for_prompt(cwe_value) -> str:
    """Mirror llm_manager.py:1543-1561 normalisation."""
    if cwe_value is None:
        return "CWE"
    s = str(cwe_value).strip()
    if not s:
        return "CWE"
    try:
        parsed = json.loads(s)
        if isinstance(parsed, list):
            xs = [str(x).strip() for x in parsed if str(x).strip()]
            return " or ".join(xs) if xs else "CWE"
        return str(parsed).strip() or "CWE"
    except json.JSONDecodeError:
        s = s.strip("[]")
        xs = [p.strip() for p in s.replace(";", ",").split(",") if p.strip()]
        return " or ".join(xs) if xs else "CWE"


def build_prompt(task: str, row: dict) -> Optional[str]:
    """Reconstruct the exact prompt string the manager would send."""
    if task == "is_vulnerable_vuln":
        code = row.get("VULNERABLE_CODE_BLOCK")
        if not code:
            return None
        return PROMPT_VULN.format(code_block=code)
    if task == "is_vulnerable_patch":
        code = row.get("PATCHED_CODE_BLOCK")
        if not code:
            return None
        return PROMPT_VULN.format(code_block=code)
    if task == "is_vulnerable_vuln_cve_cwe":
        code = row.get("VULNERABLE_CODE_BLOCK")
        if not code:
            return None
        cve = row.get("VULNERABILITY_CVE") or "UNKNOWN-CVE"
        cwe_list = normalise_cwe_for_prompt(row.get("VULNERABILITY_CWE"))
        return PROMPT_CVE_CWE.format(code_block=code, cve=cve, cwe_list=cwe_list)
    if task == "is_vulnerable_patch_cve_cwe":
        code = row.get("PATCHED_CODE_BLOCK")
        if not code:
            return None
        cve = row.get("VULNERABILITY_CVE") or "UNKNOWN-CVE"
        cwe_list = normalise_cwe_for_prompt(row.get("VULNERABILITY_CWE"))
        return PROMPT_CVE_CWE.format(code_block=code, cve=cve, cwe_list=cwe_list)
    raise ValueError(f"unknown task {task}")


def file_sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_dataset_rows(model: str, dataset: str) -> list[dict]:
    """Load every PBD or LFD row, ordered by id ASC (matches scheduler order)."""
    name = DB_FILENAME[model]
    if dataset == "LFD":
        name = name.replace(".sqlite", "_leakagefree.sqlite")
    candidates = [RESULTS / name]
    # Some LFD DBs were moved to results/output/leakagefree/ during
    # reorganisation; try that fallback.
    if dataset == "LFD":
        candidates.append(RESULTS / "leakagefree" / name)
    cols = (
        "id, COMMIT_HASH, VULNERABILITY_CVE, VULNERABILITY_CWE, "
        "VULNERABLE_CODE_BLOCK, PATCHED_CODE_BLOCK, "
        "NUM_FILES_CHANGED, NUM_FUNCTIONS_CHANGED, "
        "NUM_LINES_IN_VULNERABLE_CODE_BLOCK, NUM_LINES_IN_PATCHED_CODE_BLOCK, "
        "LLM_Ranked_CWE"
    )
    keys = [c.strip() for c in cols.split(",")]
    last_err: Exception | None = None
    for path in candidates:
        if not path.is_file():
            continue
        try:
            conn = sqlite3.connect(path)
            cur = conn.cursor()
            cur.execute(f"SELECT {cols} FROM vulnerabilities ORDER BY id ASC")
            rows = [dict(zip(keys, r)) for r in cur.fetchall()]
            conn.close()
            if rows:
                return rows
            warnings.warn(f"[load] {path} returned 0 rows; trying next candidate")
        except sqlite3.OperationalError as e:
            last_err = e
            warnings.warn(f"[load] {path} unusable: {e}; trying next candidate")
    raise FileNotFoundError(
        f"no usable DB for {model}/{dataset}; tried {candidates}; last_err={last_err}"
    )


# ---------------------------------------------------------------------------
# Phase 1: token analysis
# ---------------------------------------------------------------------------

def _quantiles(values: list[int]) -> dict:
    if not values:
        return {"n": 0, "median": 0.0, "p95": 0.0, "mean": 0.0, "max": 0}
    s = sorted(values)
    n = len(s)
    return {
        "n": n,
        "median": float(s[n // 2]),
        "p95": float(s[min(int(0.95 * (n - 1)), n - 1)]),
        "mean": float(mean(s)),
        "max": int(s[-1]),
    }


def _make_oss_tokenizer(hf_id: str):
    """Load the model's HF tokenizer from the cache. CPU-only."""
    from transformers import AutoTokenizer
    cache = "/scratch/azibaeir/cache/huggingface"
    return AutoTokenizer.from_pretrained(
        hf_id,
        cache_dir=cache,
        trust_remote_code=True,
    )


def _make_gpt_tokenizer():
    import tiktoken
    return tiktoken.get_encoding("o200k_base")


def _count_tokens(tokenizer, text: str, is_tiktoken: bool) -> int:
    if is_tiktoken:
        return len(tokenizer.encode(text))
    # transformers tokenizer
    return len(tokenizer.encode(text, add_special_tokens=False))


def phase_tokens() -> Path:
    """For each (model, dataset, task, level) compute input-token quantiles
    plus build a per-(model, dataset) per-row token vector for use by the
    latency regression."""

    out_quant = OUT_DIR / "tokens_by_model_level.csv"
    out_perrow = OUT_DIR / "tokens_per_row.jsonl"

    rows_quant: list[dict] = []
    perrow_records: list[dict] = []

    # Open-source models -- load their tokenizer once each.
    hf_token = None
    cfg = PROJECT_ROOT / "src" / "utils" / ".config"
    if cfg.is_file():
        for line in cfg.read_text().splitlines():
            line = line.strip()
            if line.startswith("HF_api_key"):
                _, _, val = line.partition("=")
                hf_token = val.strip().strip('"').strip("'")
    if hf_token:
        os.environ.setdefault("HF_TOKEN", hf_token)

    tokenizers: dict[str, tuple[object, bool]] = {}
    for m, info in OSS_MODELS.items():
        try:
            tokenizers[m] = (_make_oss_tokenizer(info["hf_id"]), False)
        except Exception as e:  # noqa: BLE001
            warnings.warn(f"[tokens] failed to load tokenizer for {m}: {e}")
    try:
        tokenizers["gpt-4.1-mini"] = (_make_gpt_tokenizer(), True)
    except Exception as e:  # noqa: BLE001
        warnings.warn(f"[tokens] tiktoken unavailable: {e}")

    print(f"[tokens] tokenizers loaded: {sorted(tokenizers)}")

    for model, (tk, is_tk) in tokenizers.items():
        for dataset in ("PBD", "LFD"):
            try:
                rows = load_dataset_rows(
                    "gpt-4.1-mini" if model == "gpt-4.1-mini" else model,
                    dataset,
                )
            except FileNotFoundError as e:
                warnings.warn(f"[tokens] DB missing for {model}/{dataset}: {e}")
                continue

            # Bucket vectors per (task, level)
            buckets: dict[tuple[str, str], list[int]] = defaultdict(list)

            for r in rows:
                files = int(r.get("NUM_FILES_CHANGED") or 1)
                funcs = int(r.get("NUM_FUNCTIONS_CHANGED") or 1)
                level = categorise(files, funcs)

                # Token count per task
                per_row = {
                    "model": model,
                    "dataset": dataset,
                    "id": r["id"],
                    "commit_hash": r["COMMIT_HASH"],
                    "level": level,
                    "files": files,
                    "funcs": funcs,
                }
                for task in TASKS:
                    prompt = build_prompt(task, r)
                    if prompt is None:
                        continue
                    n_tokens = _count_tokens(tk, prompt, is_tk)
                    buckets[(task, level)].append(n_tokens)
                    per_row[f"tokens_{task}"] = n_tokens
                perrow_records.append(per_row)

            for (task, level), vec in buckets.items():
                q = _quantiles(vec)
                rows_quant.append({
                    "model": model,
                    "dataset": dataset,
                    "task": task,
                    "level": level,
                    **q,
                })

    rows_quant.sort(key=lambda r: (r["model"], r["dataset"], r["task"], r["level"]))
    with out_quant.open("w", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["model", "dataset", "task", "level", "n",
                        "median", "p95", "mean", "max"],
        )
        writer.writeheader()
        writer.writerows(rows_quant)
    print(f"[tokens] wrote {out_quant} ({len(rows_quant)} rows)")

    with out_perrow.open("w") as fh:
        for rec in perrow_records:
            fh.write(json.dumps(rec) + "\n")
    print(f"[tokens] wrote {out_perrow} ({len(perrow_records)} rows)")
    return out_quant


# ---------------------------------------------------------------------------
# Phase 2: latency regression
# ---------------------------------------------------------------------------

LOG_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}),\d+\s-\s.*?\s-\sINFO\s-\s"
    r"(?:Task\s(?P<task>\S+):\s(?P<n>\d+)/(?P<total>\d+)\scommits processed"
    r"|(?P<start>Starting task: (?P<starttask>\S+))"
    r"|(?P<done>Completed task: (?P<donetask>\S+)))"
)


def _parse_log(log_path: Path) -> list[dict]:
    """Extract per-window timestamps for each task in one log file.

    Returns list of dicts: {model, dataset, task, log, marker_n, ts_seconds}.
    """
    name = log_path.name  # e.g. llama_database_1764225093.log
    # model name = portion before '_database'
    m = re.match(r"^(.+?)_database(?:_leakagefree)?_\d+\.log$", name)
    if not m:
        return []
    model = m.group(1)
    dataset = "LFD" if "_leakagefree_" in name else "PBD"
    out: list[dict] = []
    cur_task: Optional[str] = None
    with log_path.open() as fh:
        for line in fh:
            m = LOG_LINE_RE.match(line.rstrip())
            if not m:
                continue
            ts_str = m.group(1)
            ts = _dt.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            ts_seconds = ts.timestamp()
            if m.group("starttask"):
                cur_task = m.group("starttask")
            elif m.group("donetask"):
                cur_task = None
            elif m.group("task"):
                t = m.group("task")
                marker_n = int(m.group("n"))
                marker_total = int(m.group("total"))
                out.append(
                    {
                        "model": model,
                        "dataset": dataset,
                        "task": t,
                        "log": name,
                        "marker_n": marker_n,
                        "marker_total": marker_total,
                        "ts_seconds": ts_seconds,
                    }
                )
                cur_task = t
    return out


def _per_row_tokens(perrow_path: Path) -> dict[tuple[str, str], list[dict]]:
    """Index per-row token records by (model, dataset)."""
    by_md: dict[tuple[str, str], list[dict]] = defaultdict(list)
    with perrow_path.open() as fh:
        for line in fh:
            r = json.loads(line)
            by_md[(r["model"], r["dataset"])].append(r)
    # sort each list by id ASC (matches scheduler's natural ordering)
    for k in by_md:
        by_md[k].sort(key=lambda r: r["id"])
    return by_md


def _ols(xs: list[float], ys: list[float]) -> tuple[float, float, float]:
    """Return (alpha, beta, r2) for y = alpha + beta * x."""
    n = len(xs)
    if n < 3:
        return 0.0, 0.0, 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    if sxx == 0 or syy == 0:
        return my, 0.0, 0.0
    beta = sxy / sxx
    alpha = my - beta * mx
    r2 = (sxy ** 2) / (sxx * syy)
    return alpha, beta, r2


def phase_latency() -> Path:
    """Build per-(model, dataset, task) latency regression."""
    perrow_path = OUT_DIR / "tokens_per_row.jsonl"
    if not perrow_path.is_file():
        print("[latency] running phase_tokens first...")
        phase_tokens()

    perrow = _per_row_tokens(perrow_path)
    # Index by (model_alias, dataset) for log->tokens join. Note logs use model
    # aliases like "qwen3_coder", "llama", which match our keys.

    log_records: list[dict] = []
    for log in sorted(LOGS_DIR.glob("*.log")):
        log_records.extend(_parse_log(log))
    print(f"[latency] parsed {len(log_records)} marker lines from {len(list(LOGS_DIR.glob('*.log')))} logs")

    # Group markers by (model, dataset, task, log) and sort by marker_n
    grouped: dict[tuple[str, str, str, str], list[dict]] = defaultdict(list)
    for r in log_records:
        grouped[(r["model"], r["dataset"], r["task"], r["log"])].append(r)
    for v in grouped.values():
        v.sort(key=lambda r: r["marker_n"])

    # Compute windows per (model, dataset, task) -- pool only over FRESH RUNS.
    # A fresh run is a log whose markers start at 10 and cover the dataset
    # monotonically in steps of 10 to within 80% of the total. Resume runs
    # report markers that count from 1 in the new run, so their N/total marker
    # does NOT correspond to absolute sample id N -- their token-sum join would
    # be wrong. We exclude them.
    windows: dict[tuple[str, str, str], list[tuple[float, float]]] = defaultdict(list)
    fresh_logs: dict[tuple[str, str, str], list[str]] = defaultdict(list)

    for (model, dataset, task, log), markers in grouped.items():
        if len(markers) < 5:
            continue
        rows_md = perrow.get((model, dataset))
        if not rows_md:
            rows_md = perrow.get((f"{model}-mini", dataset))
        if not rows_md:
            continue
        token_col = f"tokens_{task}"
        ordered_tokens = [r.get(token_col) for r in rows_md if r.get(token_col) is not None]
        if not ordered_tokens:
            continue

        # Fresh-run detection: this log's run total must equal the dataset
        # size and markers must form a strictly monotonic 10-step sequence
        # starting at 10, covering at least 80% of the dataset.
        totals = {m["marker_total"] for m in markers}
        if len(totals) != 1:
            continue
        run_total = next(iter(totals))
        if run_total != len(ordered_tokens):
            continue
        ms = [m["marker_n"] for m in markers]
        if ms[0] != 10:
            continue
        gaps = [b - a for a, b in zip(ms, ms[1:])]
        if any(g != 10 for g in gaps):
            continue
        if ms[-1] < 0.8 * run_total:
            continue

        fresh_logs[(model, dataset, task)].append(log)

        for i in range(1, len(markers)):
            prev = markers[i - 1]
            curr = markers[i]
            dt = curr["ts_seconds"] - prev["ts_seconds"]
            if dt <= 0 or dt > 7200:
                continue
            n_lo = prev["marker_n"]
            n_hi = curr["marker_n"]
            if n_hi - n_lo != 10:
                continue
            if n_hi > len(ordered_tokens):
                continue
            window_token_sum = sum(ordered_tokens[n_lo:n_hi])
            if window_token_sum == 0:
                continue
            windows[(model, dataset, task)].append((float(window_token_sum), float(dt)))

    # Diagnostic: how many fresh logs survived per (model, dataset, task)?
    n_keys = len(windows)
    n_logs_used = sum(len(v) for v in fresh_logs.values())
    print(f"[latency] fresh runs accepted: {n_logs_used} logs across {n_keys} (model, dataset, task) tuples")

    print(f"[latency] built windows for {len(windows)} (model, dataset, task) tuples")

    # Fit OLS for each tuple
    out_reg = OUT_DIR / "latency_regression.csv"
    out_lvl = OUT_DIR / "latency_by_level.csv"

    reg_rows: list[dict] = []
    for key, pts in sorted(windows.items()):
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        alpha, beta, r2 = _ols(xs, ys)
        reg_rows.append({
            "model": key[0],
            "dataset": key[1],
            "task": key[2],
            "n_windows": len(pts),
            "alpha_sec": round(alpha, 4),
            "beta_sec_per_token": round(beta, 6),
            "r2": round(r2, 4),
            "median_window_tokens": round(median(xs), 1),
            "median_window_sec": round(median(ys), 3),
        })

    with out_reg.open("w", newline="") as fh:
        if reg_rows:
            writer = csv.DictWriter(fh, fieldnames=list(reg_rows[0].keys()))
            writer.writeheader()
            writer.writerows(reg_rows)
    print(f"[latency] wrote {out_reg} ({len(reg_rows)} rows)")

    # Project per-level latency. To do so we need each model's
    # (dataset, task, level) median tokens.
    quant_rows: list[dict] = []
    with (OUT_DIR / "tokens_by_model_level.csv").open() as fh:
        for r in csv.DictReader(fh):
            quant_rows.append(r)

    medians: dict[tuple[str, str, str, str], float] = {}
    for r in quant_rows:
        medians[(r["model"], r["dataset"], r["task"], r["level"])] = float(r["median"])

    # Compute alpha/beta accessor with fallback per (model, dataset)
    reg_lookup: dict[tuple[str, str, str], dict] = {
        (r["model"], r["dataset"], r["task"]): r for r in reg_rows
    }

    # Project per-level latency. Two estimators:
    #   (1) regression: latency_per_sample = (alpha + beta * 10 * median_tokens) / 10
    #   (2) ratio:      latency_per_sample = (global_median_window_sec / 10) * (median_tokens / global_median_tokens_per_sample)
    # The ratio estimator is robust to: (a) coarse 1-sec log timestamps that
    # mask token-level slope, (b) reasoning models (DeepSeek-R1, Qwen3-Coder)
    # whose output-token decoding dominates wall-clock and breaks the
    # input-token regression. The regression is reported alongside as a
    # sanity check; in the paper we recommend the ratio estimator as the
    # primary number with a clear caveat.
    lvl_rows: list[dict] = []
    for (model, dataset, task, level), tk_med in medians.items():
        reg = reg_lookup.get((model, dataset, task))
        if reg is None:
            continue
        alpha = float(reg["alpha_sec"])
        beta = float(reg["beta_sec_per_token"])
        global_med_window_tokens = float(reg["median_window_tokens"])
        global_med_window_sec = float(reg["median_window_sec"])
        global_lat_per_sample = global_med_window_sec / 10.0
        global_tokens_per_sample = global_med_window_tokens / 10.0

        win_tokens = 10.0 * tk_med
        lat_reg = max(0.0, (alpha + beta * win_tokens) / 10.0)
        if global_tokens_per_sample > 0:
            lat_ratio = global_lat_per_sample * (tk_med / global_tokens_per_sample)
        else:
            lat_ratio = float("nan")

        lvl_rows.append({
            "model": model,
            "dataset": dataset,
            "task": task,
            "level": level,
            "median_tokens_per_sample": round(tk_med, 1),
            "global_avg_tokens_per_sample": round(global_tokens_per_sample, 1),
            "global_avg_latency_sec": round(global_lat_per_sample, 3),
            "ratio_latency_sec_per_sample": round(lat_ratio, 3),
            "regression_latency_sec_per_sample": round(lat_reg, 3),
            "n_windows": int(reg["n_windows"]),
            "r2": float(reg["r2"]),
        })

    with out_lvl.open("w", newline="") as fh:
        if lvl_rows:
            writer = csv.DictWriter(fh, fieldnames=list(lvl_rows[0].keys()))
            writer.writeheader()
            writer.writerows(lvl_rows)
    print(f"[latency] wrote {out_lvl} ({len(lvl_rows)} rows)")
    return out_lvl


# ---------------------------------------------------------------------------
# Phase 3: cost rollup
# ---------------------------------------------------------------------------

def phase_costs() -> Path:
    """Translate latency + tokens into deployment cost ($/pred, preds/min)."""
    out_path = OUT_DIR / "cost_per_prediction.csv"

    # Collect all level tokens for GPT and OSS
    lvl_tokens: dict[tuple[str, str, str, str], float] = {}
    with (OUT_DIR / "tokens_by_model_level.csv").open() as fh:
        for r in csv.DictReader(fh):
            lvl_tokens[(r["model"], r["dataset"], r["task"], r["level"])] = float(r["median"])

    # OSS latency: use ratio estimator (robust to 1-sec log granularity and
    # to reasoning models where output-token decoding dominates wall-clock).
    oss_lat: dict[tuple[str, str, str, str], float] = {}
    if (OUT_DIR / "latency_by_level.csv").is_file():
        with (OUT_DIR / "latency_by_level.csv").open() as fh:
            for r in csv.DictReader(fh):
                oss_lat[(r["model"], r["dataset"], r["task"], r["level"])] = (
                    float(r["ratio_latency_sec_per_sample"])
                )

    rows: list[dict] = []
    for (model, dataset, task, level), tk_med in lvl_tokens.items():
        # Output-token budget. The prompt asks for a single token ("0", "1",
        # or "not sure"), but in practice models emit longer prose that the
        # production VulnerabilityOutputParser then filters down to a label;
        # those extra tokens are billed by the API. We therefore report the
        # production cap (max_new_tokens=512 in llm_manager.py) as the
        # worst-case billed output and a smaller "format-compliant" budget
        # of 8 tokens as a lower bound. The paper uses the worst case.
        out_tokens_typical = 8
        out_tokens_worst = 512
        rec: dict = {
            "model": model,
            "dataset": dataset,
            "task": task,
            "level": level,
            "median_input_tokens": round(tk_med, 1),
            "out_tokens_typical": out_tokens_typical,
            "out_tokens_worst": out_tokens_worst,
        }
        if model == "gpt-4.1-mini":
            p_in = PRICING["gpt-4.1-mini"]["input_per_1m_usd"]
            p_out = PRICING["gpt-4.1-mini"]["output_per_1m_usd"]
            cost_typ = (tk_med * p_in + out_tokens_typical * p_out) / 1e6
            cost_worst = (tk_med * p_in + out_tokens_worst * p_out) / 1e6
            rec["usd_per_prediction_typical"] = round(cost_typ, 7)
            rec["usd_per_prediction_worst"] = round(cost_worst, 6)
            rec["usd_per_1k_predictions_typical"] = round(cost_typ * 1000, 4)
            # Vendor-quoted wall-clock
            lat = GPT41_MINI_VENDOR_LATENCY_S.get(level, float("nan"))
            rec["latency_sec"] = lat
            rec["latency_source"] = "vendor_quoted"
            rec["preds_per_minute"] = round(60 / lat, 1) if lat == lat and lat > 0 else None
        else:
            lat = oss_lat.get((model, dataset, task, level))
            if lat is None:
                continue
            gpu = OSS_MODELS.get(model, {}).get("deploy_gpu", "L40S")
            usd_hr = PRICING[gpu]["usd_per_hour"]
            cost_pred = (lat * usd_hr) / 3600
            rec["latency_sec"] = round(lat, 3)
            rec["latency_source"] = "regression_measured"
            rec["gpu"] = gpu
            rec["usd_per_gpu_hour"] = usd_hr
            rec["usd_per_prediction"] = round(cost_pred, 6)
            rec["usd_per_1k_predictions"] = round(cost_pred * 1000, 3)
            rec["preds_per_minute"] = round(60 / lat, 1) if lat > 0 else None
        rows.append(rec)

    rows.sort(key=lambda r: (r["model"], r["dataset"], r["task"], r["level"]))
    if rows:
        keys: list[str] = []
        for r in rows:
            for k in r:
                if k not in keys:
                    keys.append(k)
        with out_path.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
    print(f"[costs] wrote {out_path} ({len(rows)} rows)")
    return out_path


# ---------------------------------------------------------------------------
# Phase 4: paper table
# ---------------------------------------------------------------------------

def phase_paper_table() -> Path:
    """Emit a compact LaTeX table for the paper appendix.

    Columns:
        Model | Median tokens (L1, L3) | L1 latency (s) | L3 latency (s) |
        L3/L1 ratio | $/1k preds at L3
    Restrict to dataset = PBD, task = is_vulnerable_vuln (the most common
    deployment configuration).
    """
    out_path = OUT_DIR / "table_v_cost_latency.tex"

    # Build a (model -> level -> {tokens, lat, $/1k}) view restricted to
    # dataset=PBD, task=is_vulnerable_vuln.
    view: dict[str, dict[str, dict]] = defaultdict(dict)
    if (OUT_DIR / "cost_per_prediction.csv").is_file():
        with (OUT_DIR / "cost_per_prediction.csv").open() as fh:
            for r in csv.DictReader(fh):
                if r["dataset"] != "PBD":
                    continue
                if r["task"] != "is_vulnerable_vuln":
                    continue
                view[r["model"]][r["level"]] = r

    pretty = {
        "llama":         "Llama3.1-8B",
        "mistral":       "Mistral-7B-v0.3",
        "deepseek":      "DeepSeek-R1-Distill",
        "starcoder":     "StarCoder2-7B",
        "codellama":     "CodeLlama-7B",
        "qwen3_coder":   "Qwen3-Coder-30B",
        "gpt-4.1-mini":  "GPT-4.1-mini",
    }
    order = ["gpt-4.1-mini", "llama", "mistral", "deepseek",
             "starcoder", "codellama", "qwen3_coder"]

    lines: list[str] = [
        "% Auto-generated by experiments/analysis/cost_latency_analysis.py --- DO NOT EDIT BY HAND",
        "\\begin{table}[!t]",
        "\\centering",
        "\\caption{Per-prediction cost and inference time on the non-targeted "
        "SVD task (\\texttt{is\\_vulnerable\\_vuln}, PBD), broken down by "
        "abstraction level. \\textbf{Tokens}: median input prompt tokens at "
        "L1 / L3. \\textbf{Latency}: per-prediction wall-clock derived by "
        "scaling each model's globally measured average sample latency by "
        "the level-median input-token ratio (full method in "
        "Appendix~\\ref{appendix:cost-latency}); GPT-4.1-mini latency is the "
        "vendor-quoted p50 from OpenAI's status page (retrieved 2026-05-06). "
        "\\textbf{L3/L1}: ratio of L3 to L1 latency. \\textbf{\\$/1k preds (L3)}: "
        "1{,}000 predictions at L3 in USD; for GPT-4.1-mini at OpenAI public "
        "pricing, for the open-source models at RunPod community spot prices "
        "for the deployment GPU (L40S for the 7--8B models, A100 80G for "
        "Qwen3-Coder-30B).}",
        "\\label{tab:cost_latency}",
        "\\small",
        "\\setlength{\\tabcolsep}{4pt}",
        "\\begin{tabular}{@{}lrrrrrr@{}}",
        "\\toprule",
        "\\multirow{2}{*}{\\textbf{Model}} & "
        "\\multicolumn{2}{c}{\\textbf{Tokens}} & "
        "\\multicolumn{2}{c}{\\textbf{Latency (s)}} & "
        "\\multirow{2}{*}{\\textbf{L3/L1}} & "
        "\\multirow{2}{*}{\\textbf{\\$/1k preds (L3)}} \\\\",
        "\\cmidrule(lr){2-3} \\cmidrule(lr){4-5}",
        " & \\textbf{L1} & \\textbf{L3} & "
        "\\textbf{L1} & \\textbf{L3} & & \\\\",
        "\\midrule",
    ]
    for m in order:
        if m not in view:
            continue
        l1 = view[m].get("L1")
        l3 = view[m].get("L3")
        if not l1 or not l3:
            continue
        l1_tok = float(l1["median_input_tokens"])
        l3_tok = float(l3["median_input_tokens"])
        l1_lat = float(l1.get("latency_sec", "nan"))
        l3_lat = float(l3.get("latency_sec", "nan"))
        ratio = (l3_lat / l1_lat) if l1_lat > 0 else float("nan")
        if m == "gpt-4.1-mini":
            # Use the worst-case (max_new_tokens=512) output budget, since
            # the model's full response is billed; only the parsed verdict
            # is read. Stored in cost_per_prediction.csv as the "_worst" col.
            cost_l3_pred = float(l3.get("usd_per_prediction_worst", "0"))
            cost_l3_1k = cost_l3_pred * 1000
        else:
            cost_l3_1k = float(l3.get("usd_per_1k_predictions", "0"))
        lines.append(
            f"{pretty[m]} & {l1_tok:.0f} & {l3_tok:.0f} & "
            f"{l1_lat:.2f} & {l3_lat:.2f} & {ratio:.1f}$\\times$ & "
            f"\\${cost_l3_1k:.2f} \\\\"
        )
    lines += [
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ]
    out_path.write_text("\n".join(lines) + "\n")
    print(f"[paper-table] wrote {out_path}")
    return out_path


# ---------------------------------------------------------------------------
# Phase 5: manifest
# ---------------------------------------------------------------------------

def phase_manifest() -> Path:
    out_path = OUT_DIR / "manifest.json"
    inputs = []
    for db in (RESULTS).glob("database_*_database*.sqlite"):
        try:
            inputs.append({
                "path": str(db.relative_to(PROJECT_ROOT)),
                "sha256": file_sha256(db),
                "size_bytes": db.stat().st_size,
            })
        except OSError:
            pass

    log_count = len(list(LOGS_DIR.glob("*.log")))
    versions = {}
    try:
        import transformers
        versions["transformers"] = transformers.__version__
    except Exception:  # noqa: BLE001
        versions["transformers"] = "unavailable"
    try:
        import tiktoken
        versions["tiktoken"] = tiktoken.__version__
    except Exception:  # noqa: BLE001
        versions["tiktoken"] = "unavailable"

    manifest = {
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "project_root": str(PROJECT_ROOT),
        "n_logs_parsed": log_count,
        "pricing_snapshot": PRICING,
        "gpt41_mini_vendor_latency_s": GPT41_MINI_VENDOR_LATENCY_S,
        "tool_versions": versions,
        "inputs": inputs[:20],
        "n_inputs_total": len(inputs),
    }
    out_path.write_text(json.dumps(manifest, indent=2))
    print(f"[manifest] wrote {out_path}")
    return out_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

PHASES = {
    "tokens": phase_tokens,
    "latency": phase_latency,
    "costs": phase_costs,
    "paper-table": phase_paper_table,
    "manifest": phase_manifest,
}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument(
        "phase",
        choices=list(PHASES) + ["all"],
        help="Which phase to run, or 'all' to run the entire pipeline.",
    )
    args = p.parse_args()
    if args.phase == "all":
        phase_tokens()
        phase_latency()
        phase_costs()
        phase_paper_table()
        phase_manifest()
    else:
        PHASES[args.phase]()
    return 0


if __name__ == "__main__":
    sys.exit(main())

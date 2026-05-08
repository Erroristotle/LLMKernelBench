"""Correlate LLMKernelBench and XSTest refusal rates for the 3-model study."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "experiments" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from refusal_taxonomy_classify import is_safety_refusal  # noqa: E402


def _read_summary(summary_path: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    with summary_path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            if row.get("framing") != "neutral":
                continue
            model = str(row["model"])
            rows[model] = row
    return rows


def _read_xstest_rates(input_dir: Path) -> dict[str, dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()
    for path in sorted(input_dir.rglob("*.jsonl")):
        if path.name.startswith("manifest"):
            continue
        with path.open() as fh:
            for line in fh:
                rec = json.loads(line)
                if rec.get("task") != "xstest":
                    continue
                model = str(rec.get("model"))
                key = str(rec.get("record_key"))
                dedupe_key = (model, key)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                grouped[model].append(rec)

    rates: dict[str, dict] = {}
    for model, records in sorted(grouped.items()):
        counts = Counter()
        for rec in records:
            raw = rec.get("raw_response")
            if raw is None or str(raw).startswith("<<GENERATION_ERROR"):
                counts["generation_error"] += 1
            elif is_safety_refusal(str(raw)):
                counts["safety_refusal"] += 1
            else:
                counts["non_refusal"] += 1
        n = len(records)
        rates[model] = {
            "model": model,
            "xstest_n": n,
            "xstest_safety_refusal": counts["safety_refusal"],
            "xstest_generation_error": counts["generation_error"],
            "xstest_refusal_pct": 100 * counts["safety_refusal"] / n if n else 0.0,
        }
    return rates


def _spearman(xs: list[float], ys: list[float]) -> tuple[float, float | None]:
    try:
        from scipy.stats import spearmanr

        res = spearmanr(xs, ys)
        rho = float(res.statistic)
        pvalue = float(res.pvalue)
        if math.isnan(rho):
            rho = 0.0
        if math.isnan(pvalue):
            pvalue = None
        return rho, pvalue
    except Exception:
        return _spearman_no_scipy(xs, ys), None


def _spearman_no_scipy(xs: list[float], ys: list[float]) -> float:
    def ranks(values: list[float]) -> list[float]:
        ordered = sorted((value, idx) for idx, value in enumerate(values))
        out = [0.0] * len(values)
        i = 0
        while i < len(ordered):
            j = i
            while j + 1 < len(ordered) and ordered[j + 1][0] == ordered[i][0]:
                j += 1
            avg = (i + j + 2) / 2.0
            for _, idx in ordered[i : j + 1]:
                out[idx] = avg
            i = j + 1
        return out

    rx = ranks(xs)
    ry = ranks(ys)
    mx = sum(rx) / len(rx)
    my = sum(ry) / len(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den_x = math.sqrt(sum((a - mx) ** 2 for a in rx))
    den_y = math.sqrt(sum((b - my) ** 2 for b in ry))
    if den_x == 0 or den_y == 0:
        return 0.0
    return num / (den_x * den_y)


def write_model_rates(llmk: dict[str, dict], xstest: dict[str, dict], out_path: Path):
    fields = [
        "model",
        "llmk_n",
        "llmk_parser_abstention_pct",
        "llmk_safety_refusal_pct",
        "xstest_n",
        "xstest_refusal_pct",
        "xstest_safety_refusal",
        "xstest_generation_error",
    ]
    rows = []
    for model in sorted(set(llmk) & set(xstest)):
        row = {
            "model": model,
            "llmk_n": llmk[model]["n"],
            "llmk_parser_abstention_pct": llmk[model]["parser_abstention_pct"],
            "llmk_safety_refusal_pct": llmk[model]["safety_refusal_pct"],
            "xstest_n": xstest[model]["xstest_n"],
            "xstest_refusal_pct": f"{xstest[model]['xstest_refusal_pct']:.2f}",
            "xstest_safety_refusal": xstest[model]["xstest_safety_refusal"],
            "xstest_generation_error": xstest[model]["xstest_generation_error"],
        }
        rows.append(row)
    with out_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"[ok] wrote {out_path}")
    return rows


def write_correlation(rows: list[dict], out_path: Path) -> None:
    metrics = [
        ("llmk_parser_abstention_pct", "xstest_refusal_pct"),
        ("llmk_safety_refusal_pct", "xstest_refusal_pct"),
    ]
    fields = ["x_metric", "y_metric", "n_models", "spearman_rho", "pvalue", "note"]
    with out_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for x_key, y_key in metrics:
            xs = [float(row[x_key]) for row in rows]
            ys = [float(row[y_key]) for row in rows]
            rho, pvalue = _spearman(xs, ys)
            writer.writerow(
                {
                    "x_metric": x_key,
                    "y_metric": y_key,
                    "n_models": len(rows),
                    "spearman_rho": f"{rho:.4f}",
                    "pvalue": "" if pvalue is None else f"{pvalue:.4f}",
                    "note": "descriptive only; n=3 is too small for significance claims",
                }
            )
    print(f"[ok] wrote {out_path}")


def write_markdown(rows: list[dict], correlation_path: Path, out_path: Path) -> None:
    try:
        correlation_display = str(correlation_path.relative_to(PROJECT_ROOT))
    except ValueError:
        correlation_display = str(correlation_path)
    lines = [
        "# Refusal Correlation",
        "",
        "This is descriptive only because the planned open-source subset has n=3 models.",
        "Do not claim p <= 0.05 from this analysis.",
        "",
        "## Model Rates",
        "",
        "| Model | LLMKernelBench parser abst. % | LLMKernelBench safety refus. % | XSTest refus. % |",
        "|---|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['model']} | {row['llmk_parser_abstention_pct']} | "
            f"{row['llmk_safety_refusal_pct']} | {row['xstest_refusal_pct']} |"
        )
    lines += [
        "",
        f"Correlation CSV: `{correlation_display}`",
    ]
    out_path.write_text("\n".join(lines) + "\n")
    print(f"[ok] wrote {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--llmk-summary",
        default=str(PROJECT_ROOT / "results" / "refusal_taxonomy" / "summary.csv"),
    )
    parser.add_argument(
        "--xstest-input-dir",
        default=str(PROJECT_ROOT / "results" / "safety_bench" / "xstest"),
    )
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_ROOT / "results" / "safety_bench" / "xstest"),
    )
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    llmk = _read_summary(Path(args.llmk_summary))
    xstest = _read_xstest_rates(Path(args.xstest_input_dir))
    rows = write_model_rates(llmk, xstest, out_dir / "model_refusal_rates.csv")
    correlation_path = out_dir / "correlation.csv"
    write_correlation(rows, correlation_path)
    write_markdown(rows, correlation_path, out_dir / "correlation.md")


if __name__ == "__main__":
    main()

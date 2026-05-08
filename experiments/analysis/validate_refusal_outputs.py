"""Validate completeness and duplicate keys for the 3-model refusal study."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODELS = ("llama", "deepseek", "qwen3_coder")
FRAMINGS = ("neutral", "defensive", "adversarial")


def validate_summary(summary_path: Path, expected_llmk: int) -> list[str]:
    errors: list[str] = []
    rows = {}
    if not summary_path.exists():
        return [f"missing summary: {summary_path}"]
    with summary_path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows[(row["model"], row["framing"])] = row
    for model in MODELS:
        for framing in FRAMINGS:
            row = rows.get((model, framing))
            if row is None:
                errors.append(f"missing LLMKernelBench row: {model}/{framing}")
                continue
            if int(row["n"]) != expected_llmk:
                errors.append(
                    f"{model}/{framing} has n={row['n']}, expected {expected_llmk}"
                )
    return errors


def validate_xstest(input_dir: Path, expected_xstest: int) -> list[str]:
    errors: list[str] = []
    counts: Counter[str] = Counter()
    seen: set[tuple[str, str]] = set()
    duplicate_count = 0
    for path in sorted(input_dir.rglob("*.jsonl")):
        if path.name.startswith("manifest"):
            continue
        with path.open() as fh:
            for line in fh:
                rec = json.loads(line)
                if rec.get("task") != "xstest":
                    continue
                key = (str(rec.get("model")), str(rec.get("record_key")))
                if key in seen:
                    duplicate_count += 1
                    continue
                seen.add(key)
                counts[str(rec.get("model"))] += 1
    if duplicate_count:
        errors.append(f"XSTest has {duplicate_count} duplicate model/record keys")
    for model in MODELS:
        if counts[model] != expected_xstest:
            errors.append(f"{model}/xstest has n={counts[model]}, expected {expected_xstest}")
    return errors


def validate_llmk_raw(input_dir: Path, expected_llmk: int) -> list[str]:
    errors: list[str] = []
    grouped: dict[tuple[str, str], set[str]] = defaultdict(set)
    duplicates = 0
    for path in sorted(input_dir.rglob("*.jsonl")):
        if path.name.startswith("manifest"):
            continue
        with path.open() as fh:
            for line in fh:
                rec = json.loads(line)
                if rec.get("task", "llmkernelbench") != "llmkernelbench":
                    continue
                key = str(rec.get("record_key"))
                group = (str(rec.get("model")), str(rec.get("framing", "neutral")))
                if key in grouped[group]:
                    duplicates += 1
                    continue
                grouped[group].add(key)
    if duplicates:
        errors.append(f"LLMKernelBench raw has {duplicates} duplicate model/framing keys")
    for model in MODELS:
        for framing in FRAMINGS:
            n = len(grouped[(model, framing)])
            if n and n != expected_llmk:
                errors.append(
                    f"{model}/{framing} raw has n={n}, expected {expected_llmk}"
                )
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--summary",
        default=str(PROJECT_ROOT / "results" / "refusal_taxonomy" / "summary.csv"),
    )
    parser.add_argument(
        "--llmk-input-dir",
        default=str(PROJECT_ROOT / "results" / "refusal_taxonomy" / "raw"),
    )
    parser.add_argument(
        "--xstest-input-dir",
        default=str(PROJECT_ROOT / "results" / "safety_bench" / "xstest" / "raw"),
    )
    parser.add_argument("--expected-llmk", type=int, default=417)
    parser.add_argument("--expected-xstest", type=int, default=450)
    args = parser.parse_args()

    errors = []
    errors += validate_llmk_raw(Path(args.llmk_input_dir), args.expected_llmk)
    errors += validate_summary(Path(args.summary), args.expected_llmk)
    errors += validate_xstest(Path(args.xstest_input_dir), args.expected_xstest)

    if errors:
        print("[fail] refusal experiment validation failed")
        for err in errors:
            print(f"- {err}")
        raise SystemExit(1)
    print("[ok] refusal experiment outputs are complete")


if __name__ == "__main__":
    main()

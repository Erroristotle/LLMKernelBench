#!/usr/bin/env python3
"""Audit genuine abstentions separately from parser-invalid responses."""

from __future__ import annotations

import argparse
import csv
import glob
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path


TASK_COLUMNS = {
    "is_vulnerable_vuln": "IS_VULNERABLE_Vuln",
    "is_vulnerable_patch": "IS_VULNERABLE_Patch",
    "is_vulnerable_vuln_cve_cwe": "IS_VULNERABLE_Vuln_CVE_CWE",
    "is_vulnerable_patch_cve_cwe": "IS_VULNERABLE_Patch_CVE_CWE",
}

MODEL_DB_NAMES = {
    "CodeLlama": "codellama",
    "DeepSeek-R1": "deepseek",
    "GPT-4.1-mini": "GPT-4.1-mini",
    "Llama3.1": "llama",
    "Mistral": "mistral",
    "Qwen3-Coder": "qwen3_coder",
    "StarCoder2": "starcoder",
}

STANDALONE_LABEL = re.compile(
    r"(?im)^\s*(?:final\s+(?:answer|verdict)\s*:\s*)?"
    r"(not\s+sure|-1|0|1)\s*[.!]?\s*$"
)

ANSWER_MARKER = re.compile(
    r"(?is)\b(?:final\s+answer|answer|response|verdict|conclusion|result)"
    r"\s*(?:is\s*)?[:\-]?\s*(?:\*\*)?\s*(not\s+sure|-1|0|1)\b"
)

UNCERTAINTY_REASON = re.compile(
    r"(?i)\b(?:"
    r"not\s+sure|"
    r"without\s+(?:more|additional|full)\s+(?:context|information)|"
    r"need\s+(?:more|additional)\s+(?:context|information)|"
    r"requires?\s+(?:more|additional|detailed)\s+(?:context|information)|"
    r"cannot\s+(?:definitively\s+|conclusively\s+)?determine|"
    r"unable\s+to\s+(?:determine|tell)|"
    r"insufficient\s+(?:context|information)|"
    r"impossible\s+to\s+say"
    r")\b"
)

# "not sure" appearing inside a C comment (*/  on its own line) or followed by
# HTML tags indicates code generation, not a genuine abstention.
CODE_CONTAMINATION = re.compile(
    r"(?m)^\s*(?:\*/|<(?:div|script|a\s|html|head|body)\b)"
)


def normalize_label(label: str) -> str:
    return "abstain" if label.lower() in {"not sure", "-1"} else label


def classify_intent(text: str) -> tuple[str, bool]:
    """Return response intent and whether it follows the one-label format."""
    stripped = text.strip()
    lowered = stripped.lower()

    if lowered in {"0", "1"}:
        return "binary", True
    if lowered in {"not sure", "-1"}:
        return "clean_abstention", True

    standalone = [normalize_label(label) for label in STANDALONE_LABEL.findall(stripped)]
    markers = [normalize_label(label) for label in ANSWER_MARKER.findall(stripped)]
    first_line = next(
        (line.strip().lower() for line in stripped.splitlines() if line.strip()),
        "",
    )

    only_abstention_labels = bool(standalone) and set(standalone) == {"abstain"}
    clear_abstention_position = (
        first_line in {"not sure", "-1"}
        or (bool(markers) and markers[-1] == "abstain")
    )
    if (
        only_abstention_labels
        and clear_abstention_position
        and UNCERTAINTY_REASON.search(stripped)
        and not CODE_CONTAMINATION.search(stripped)
    ):
        return "verbose_abstention", False

    return "invalid_or_indeterminate", False


def load_raw_responses(run_dir: Path) -> dict[tuple[str, str, str, str], str]:
    """Load the last logged response for each model/dataset/commit/task."""
    responses: dict[tuple[str, str, str, str], str] = {}
    pattern = str(run_dir / "raw_responses" / "*.jsonl")
    for filename in sorted(glob.glob(pattern)):
        dataset = "LFD" if "leakagefree" in Path(filename).name else "PBD"
        with open(filename, encoding="utf-8") as handle:
            for line in handle:
                record = json.loads(line)
                task = record.get("task")
                if task not in TASK_COLUMNS:
                    continue
                key = (
                    str(record.get("model")),
                    dataset,
                    str(record.get("commit_hash")),
                    task,
                )
                responses[key] = str(record.get("content") or "")
    return responses


def model_db(run_dir: Path, db_name: str, dataset: str) -> Path:
    suffix = "database_leakagefree.sqlite" if dataset == "LFD" else "database.sqlite"
    return run_dir / f"database_{db_name}_{suffix}"


def audit(run_dir: Path) -> tuple[list[dict], list[dict]]:
    raw_responses = load_raw_responses(run_dir)
    details: list[dict] = []
    summaries: list[dict] = []

    for display_name, db_name in MODEL_DB_NAMES.items():
        counts: Counter[str] = Counter()

        for dataset in ("PBD", "LFD"):
            db_path = model_db(run_dir, db_name, dataset)
            if not db_path.exists():
                raise FileNotFoundError(db_path)

            columns = ", ".join(TASK_COLUMNS.values())
            with sqlite3.connect(db_path) as connection:
                rows = connection.execute(
                    f"SELECT COMMIT_HASH, {columns} FROM vulnerabilities"
                ).fetchall()

            for row in rows:
                commit_hash = str(row[0])
                for task, stored_label in zip(TASK_COLUMNS, row[1:]):
                    counts["response_total"] += 1
                    text = raw_responses.get(
                        (db_name, dataset, commit_hash, task), ""
                    )
                    intent, format_compliant = classify_intent(text)

                    # Audit candidates include real uncertainty intent and every
                    # response the production database currently calls -1.
                    if stored_label != -1 and "abstention" not in intent:
                        continue

                    category = (
                        intent
                        if "abstention" in intent
                        else "invalid_or_indeterminate"
                    )
                    counts[category] += 1
                    counts["candidate_total"] += 1

                    details.append(
                        {
                            "model": display_name,
                            "dataset": dataset,
                            "task": task,
                            "commit_hash": commit_hash,
                            "stored_label": stored_label,
                            "category": category,
                            "format_compliant": format_compliant,
                            "response": text,
                        }
                    )

        genuine = counts["clean_abstention"] + counts["verbose_abstention"]
        invalid = counts["invalid_or_indeterminate"]
        total = counts["candidate_total"]
        response_total = counts["response_total"]
        summaries.append(
            {
                "model": display_name,
                "clean_abstention": counts["clean_abstention"],
                "verbose_abstention": counts["verbose_abstention"],
                "genuine_abstention": genuine,
                "invalid_or_indeterminate": invalid,
                "candidate_total": total,
                "genuine_pct": round(100 * genuine / total, 2) if total else None,
                "invalid_pct": round(100 * invalid / total, 2) if total else None,
                "response_total": response_total,
                "genuine_all_responses_pct": round(
                    100 * genuine / response_total, 2
                ),
                "invalid_all_responses_pct": round(
                    100 * invalid / response_total, 2
                ),
            }
        )

    numeric_fields = (
        "clean_abstention",
        "verbose_abstention",
        "genuine_abstention",
        "invalid_or_indeterminate",
        "candidate_total",
        "response_total",
    )
    total_row = {
        field: sum(int(row[field]) for row in summaries) for field in numeric_fields
    }
    candidate_total = total_row["candidate_total"]
    response_total = total_row["response_total"]
    summaries.append(
        {
            "model": "TOTAL",
            **total_row,
            "genuine_pct": round(
                100 * total_row["genuine_abstention"] / candidate_total, 2
            ),
            "invalid_pct": round(
                100 * total_row["invalid_or_indeterminate"] / candidate_total, 2
            ),
            "genuine_all_responses_pct": round(
                100 * total_row["genuine_abstention"] / response_total, 2
            ),
            "invalid_all_responses_pct": round(
                100 * total_row["invalid_or_indeterminate"] / response_total, 2
            ),
        }
    )

    return summaries, details


def write_outputs(
    summaries: list[dict],
    details: list[dict],
    summary_path: Path,
    details_path: Path,
) -> None:
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summaries[0]))
        writer.writeheader()
        writer.writerows(summaries)

    with details_path.open("w", encoding="utf-8") as handle:
        for row in details:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=Path("results/output/new_results_temp0.1_run2"),
    )
    parser.add_argument(
        "--summary-out",
        type=Path,
        default=Path("results/abstention_audit/run2_summary.csv"),
    )
    parser.add_argument(
        "--details-out",
        type=Path,
        default=Path("results/abstention_audit/run2_details.jsonl"),
    )
    args = parser.parse_args()

    summaries, details = audit(args.run_dir)
    write_outputs(summaries, details, args.summary_out, args.details_out)
    print(f"Wrote {args.summary_out} and {args.details_out}")


if __name__ == "__main__":
    main()

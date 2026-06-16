"""Regenerate hierarchy proximity scores from the three CWE-ranking runs.

CWE-1000 is a directed acyclic graph rather than a strict tree: a CWE may
have multiple immediate parents and may occur under multiple root pillars.
This analysis preserves all such relations when assigning HPS credit.
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from statistics import mean


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = PROJECT_ROOT / "results" / "output"
HIERARCHY_PATH = PROJECT_ROOT / "data" / "cwe_hierarchy.json"
DEFAULT_OUT_DIR = RESULTS_DIR / "hps_scores"
RUNS = (1, 2, 3)

MODELS = {
    "GPT-4.1-mini": "GPT-4.1-mini",
    "StarCoder2": "starcoder",
    "Llama3.1": "llama",
    "Mistral": "mistral",
    "CodeLlama": "codellama",
    "Qwen3-Coder": "qwen3_coder",
    "DeepSeek-R1": "deepseek",
}

SPLITS = {
    "PBD": "",
    "LFD": "_leakagefree",
}


def parse_cwe_list(value: str) -> list[str]:
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        parsed = value
    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed if str(item).strip()]
    text = str(parsed).strip()
    return [text] if text else []


def build_relationships(
    path: Path,
) -> tuple[
    dict[str, set[str]],
    dict[str, set[str]],
    dict[str, set[str]],
]:
    hierarchy = json.loads(path.read_text(encoding="utf-8"))
    parents: dict[str, set[str]] = defaultdict(set)
    children: dict[str, set[str]] = defaultdict(set)
    roots: dict[str, set[str]] = defaultdict(set)

    def visit(
        node: dict,
        parent_id: str | None = None,
        root_id: str | None = None,
    ) -> None:
        cwe_id = node.get("id")
        if cwe_id:
            if parent_id is None:
                root_id = cwe_id
            else:
                parents[cwe_id].add(parent_id)
                children[parent_id].add(cwe_id)
            if root_id:
                roots[cwe_id].add(root_id)
            parent_id = cwe_id

        for child in node.get("children", []) or []:
            visit(child, parent_id, root_id)

    for pillar in hierarchy.get("children", []):
        visit(pillar)

    return parents, children, roots


def relationship_score(
    predicted: str,
    truth: str,
    parents: dict[str, set[str]],
    children: dict[str, set[str]],
    roots: dict[str, set[str]],
) -> float:
    if predicted == truth:
        return 1.0
    if truth in children[predicted]:
        return 0.8
    if predicted in children[truth]:
        return 0.7
    if parents[predicted] & parents[truth]:
        return 0.6
    if roots[predicted] & roots[truth]:
        return 0.4
    return 0.0


def database_path(model_stem: str, run: int, suffix: str) -> Path:
    return (
        RESULTS_DIR
        / f"new_results_temp0.1_run{run}"
        / f"database_{model_stem}_database{suffix}.sqlite"
    )


def score_database(
    path: Path,
    parents: dict[str, set[str]],
    children: dict[str, set[str]],
    roots: dict[str, set[str]],
) -> tuple[float, int]:
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            """
            SELECT LLM_Ranked_CWE, VULNERABILITY_CWE
            FROM vulnerabilities
            WHERE LLM_Ranked_CWE IS NOT NULL
              AND VULNERABILITY_CWE IS NOT NULL
            """
        ).fetchall()

    score_sum = 0.0
    prediction_count = 0
    for prediction_value, truth_value in rows:
        predictions = parse_cwe_list(prediction_value)
        truths = parse_cwe_list(truth_value)
        if not predictions or not truths:
            continue

        for predicted in predictions:
            score_sum += max(
                relationship_score(
                    predicted,
                    truth,
                    parents,
                    children,
                    roots,
                )
                for truth in truths
            )
            prediction_count += 1

    hps = 100 * score_sum / prediction_count if prediction_count else 0.0
    return hps, prediction_count


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def generate(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    parents, children, roots = build_relationships(HIERARCHY_PATH)
    per_run_rows: list[dict] = []

    for split, suffix in SPLITS.items():
        for model, stem in MODELS.items():
            for run in RUNS:
                path = database_path(stem, run, suffix)
                if not path.exists():
                    raise FileNotFoundError(path)
                hps, prediction_count = score_database(
                    path,
                    parents,
                    children,
                    roots,
                )
                per_run_rows.append(
                    {
                        "split": split,
                        "model": model,
                        "run": run,
                        "hps_pct": hps,
                        "ranked_predictions": prediction_count,
                    }
                )

    summary_rows: list[dict] = []
    for split in SPLITS:
        for model in MODELS:
            values = [
                row["hps_pct"]
                for row in per_run_rows
                if row["split"] == split and row["model"] == model
            ]
            summary_rows.append(
                {
                    "split": split,
                    "model": model,
                    "mean_hps_pct": mean(values),
                }
            )

        split_values = [
            row["mean_hps_pct"]
            for row in summary_rows
            if row["split"] == split
        ]
        summary_rows.append(
            {
                "split": split,
                "model": "Average",
                "mean_hps_pct": mean(split_values),
            }
        )

    write_csv(out_dir / "per_run.csv", per_run_rows)
    write_csv(out_dir / "model_summary.csv", summary_rows)

    manifest = {
        "runs": list(RUNS),
        "hierarchy": str(HIERARCHY_PATH.relative_to(PROJECT_ROOT)),
        "relationship_definition": {
            "exact": 1.0,
            "immediate_parent": 0.8,
            "immediate_child": 0.7,
            "shares_any_immediate_parent": 0.6,
            "shares_any_root_pillar": 0.4,
            "unrelated": 0.0,
        },
        "multi_parent_cwes": sum(len(value) > 1 for value in parents.values()),
        "multi_root_cwes": sum(len(value) > 1 for value in roots.values()),
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()
    generate(args.out_dir)


if __name__ == "__main__":
    main()

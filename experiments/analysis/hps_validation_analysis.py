"""Regenerate the HPS hierarchy-distance validation artifacts.

The paper's HPS validation uses Top-1 CWE predictions from the three ranking
runs in ``results/output/new_results_temp0.1_run{1,2,3}``. Hierarchy distance
is the shortest path in an undirected graph containing every parent-child edge
in the bundled CWE-1000 hierarchy. A virtual root connects the top-level
pillars so that cross-pillar predictions have a finite distance.

Outputs:
    results/output/hps_validation/per_run.csv
    results/output/hps_validation/model_summary.csv
    results/output/hps_validation/distance_distribution.csv
    results/output/hps_validation/manifest.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from collections import Counter, defaultdict, deque
from pathlib import Path
from statistics import mean


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = PROJECT_ROOT / "results" / "output"
HIERARCHY_PATH = PROJECT_ROOT / "data" / "cwe_hierarchy.json"
DEFAULT_OUT_DIR = RESULTS_DIR / "hps_validation"
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


def parse_cwe_list(value: str) -> list[str]:
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        parsed = value
    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed if str(item).strip()]
    text = str(parsed).strip()
    return [text] if text else []


def build_hierarchy_graph(path: Path) -> dict[str, set[str]]:
    hierarchy = json.loads(path.read_text(encoding="utf-8"))
    graph: dict[str, set[str]] = defaultdict(set)
    virtual_root = "__CWE_VIRTUAL_ROOT__"

    def visit(node: dict, parent: str | None = None) -> None:
        cwe_id = node.get("id")
        if cwe_id:
            graph[cwe_id]
            if parent:
                graph[cwe_id].add(parent)
                graph[parent].add(cwe_id)
            for child in node.get("children", []) or []:
                visit(child, cwe_id)

    for pillar in hierarchy.get("children", []):
        pillar_id = pillar.get("id")
        visit(pillar)
        if pillar_id:
            graph[virtual_root].add(pillar_id)
            graph[pillar_id].add(virtual_root)

    return graph


def shortest_distance(
    graph: dict[str, set[str]],
    source: str,
    target: str,
    cache: dict[tuple[str, str], int | None],
) -> int | None:
    key = tuple(sorted((source, target)))
    if key in cache:
        return cache[key]
    if source == target:
        cache[key] = 0
        return 0
    if source not in graph or target not in graph:
        cache[key] = None
        return None

    queue = deque([(source, 0)])
    visited = {source}
    while queue:
        node, distance = queue.popleft()
        for neighbor in graph[node]:
            if neighbor == target:
                cache[key] = distance + 1
                return distance + 1
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, distance + 1))

    cache[key] = None
    return None


def database_path(model_stem: str, run: int) -> Path:
    return (
        RESULTS_DIR
        / f"new_results_temp0.1_run{run}"
        / f"database_{model_stem}_database.sqlite"
    )


def analyze_database(
    path: Path,
    graph: dict[str, set[str]],
    distance_cache: dict[tuple[str, str], int | None],
) -> dict:
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            """
            SELECT VULNERABILITY_CWE, LLM_Ranked_CWE
            FROM vulnerabilities
            WHERE VULNERABILITY_CWE IS NOT NULL
              AND LLM_Ranked_CWE IS NOT NULL
            """
        ).fetchall()

    predictions = 0
    wrong = 0
    close = 0
    cwe119_top5 = 0
    distances: list[int] = []

    for truth_value, prediction_value in rows:
        truths = parse_cwe_list(truth_value)
        ranked = parse_cwe_list(prediction_value)
        if not truths or not ranked:
            continue

        predictions += 1
        cwe119_top5 += "CWE-119" in ranked[:5]
        top1 = ranked[0]
        if top1 in truths:
            continue

        wrong += 1
        candidate_distances = [
            shortest_distance(graph, top1, truth, distance_cache)
            for truth in truths
        ]
        measurable = [
            distance for distance in candidate_distances if distance is not None
        ]
        if measurable:
            distance = min(measurable)
            distances.append(distance)
            close += distance <= 3

    return {
        "predictions": predictions,
        "wrong": wrong,
        "close": close,
        "measurable": len(distances),
        "distance_sum": sum(distances),
        "avg_distance": mean(distances) if distances else None,
        "cwe119_top5": cwe119_top5,
        "distance_counts": Counter(distances),
    }


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def generate(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    graph = build_hierarchy_graph(HIERARCHY_PATH)
    distance_cache: dict[tuple[str, str], int | None] = {}
    results: dict[str, list[dict]] = defaultdict(list)
    per_run_rows: list[dict] = []

    for model, stem in MODELS.items():
        for run in RUNS:
            path = database_path(stem, run)
            if not path.exists():
                raise FileNotFoundError(path)
            stats = analyze_database(path, graph, distance_cache)
            results[model].append(stats)
            per_run_rows.append(
                {
                    "model": model,
                    "run": run,
                    "predictions": stats["predictions"],
                    "wrong": stats["wrong"],
                    "close_le_3": stats["close"],
                    "close_pct_of_wrong": 100 * stats["close"] / stats["wrong"],
                    "measurable": stats["measurable"],
                    "avg_distance": stats["avg_distance"],
                    "cwe119_top5": stats["cwe119_top5"],
                    "cwe119_rate_pct": (
                        100 * stats["cwe119_top5"] / stats["predictions"]
                    ),
                }
            )

    summary_rows: list[dict] = []
    overall_distance_counts: Counter = Counter()
    overall_distance_sum = 0
    overall_measurable = 0
    overall_predictions = 0.0
    overall_wrong = 0.0
    overall_close = 0.0
    overall_cwe119 = 0.0

    for model, run_stats in results.items():
        mean_predictions = mean(item["predictions"] for item in run_stats)
        mean_wrong = mean(item["wrong"] for item in run_stats)
        mean_close = mean(item["close"] for item in run_stats)
        mean_cwe119 = mean(item["cwe119_top5"] for item in run_stats)
        distance_sum = sum(item["distance_sum"] for item in run_stats)
        measurable = sum(item["measurable"] for item in run_stats)

        summary_rows.append(
            {
                "model": model,
                "mean_predictions": mean_predictions,
                "mean_wrong": mean_wrong,
                "mean_close_le_3": mean_close,
                "close_pct_of_wrong": 100 * mean_close / mean_wrong,
                "mean_measurable": mean(
                    item["measurable"] for item in run_stats
                ),
                "avg_distance": distance_sum / measurable,
                "mean_cwe119_top5": mean_cwe119,
                "cwe119_rate_pct": 100 * mean_cwe119 / mean_predictions,
            }
        )

        overall_predictions += mean_predictions
        overall_wrong += mean_wrong
        overall_close += mean_close
        overall_cwe119 += mean_cwe119
        overall_distance_sum += distance_sum
        overall_measurable += measurable
        for item in run_stats:
            overall_distance_counts.update(item["distance_counts"])

    total_run_count = len(RUNS)
    mean_measurable = overall_measurable / total_run_count
    distribution_rows: list[dict] = []
    cumulative = 0.0
    for distance in sorted(overall_distance_counts):
        mean_count = overall_distance_counts[distance] / total_run_count
        proportion = 100 * mean_count / mean_measurable
        cumulative += proportion
        distribution_rows.append(
            {
                "distance": distance,
                "mean_count": mean_count,
                "proportion_pct": proportion,
                "cumulative_pct": cumulative,
            }
        )

    write_csv(
        out_dir / "per_run.csv",
        list(per_run_rows[0]),
        per_run_rows,
    )
    write_csv(
        out_dir / "model_summary.csv",
        list(summary_rows[0]),
        summary_rows,
    )
    write_csv(
        out_dir / "distance_distribution.csv",
        list(distribution_rows[0]),
        distribution_rows,
    )

    manifest = {
        "runs": list(RUNS),
        "hierarchy": str(HIERARCHY_PATH.relative_to(PROJECT_ROOT)),
        "distance_definition": (
            "Shortest path in the undirected CWE parent-child graph, with a "
            "virtual root connecting all top-level pillars."
        ),
        "overall": {
            "mean_predictions": overall_predictions,
            "mean_wrong": overall_wrong,
            "mean_close_le_3": overall_close,
            "close_pct_of_wrong": 100 * overall_close / overall_wrong,
            "mean_measurable": mean_measurable,
            "avg_distance": overall_distance_sum / overall_measurable,
            "mean_cwe119_top5": overall_cwe119,
            "cwe119_rate_pct": 100 * overall_cwe119 / overall_predictions,
        },
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

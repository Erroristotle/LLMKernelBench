"""Minimal format-compliance control for parser-invalid LLMKernelBench rows.

This script takes rows that were invalid under the production parser in a
previous free-generation run, reloads the same code samples, and scores a
small fixed set of allowed answers. The fixed-choice scorer removes the
free-form formatting channel, so any output-format invalidity in the original
run is isolated from the model's latent preference among labels.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path

import torch

# Workaround for transformers 5.5 + torch 2.6 flex_attention import bug.
import torch.nn.attention.flex_attention as _fa

if not hasattr(_fa, "AuxRequest"):
    _fa.AuxRequest = None  # type: ignore[attr-defined]

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "experiments" / "scripts"))

from langchain_core.exceptions import OutputParserException  # noqa: E402
from models.llm_manager import VulnerabilityOutputParser  # noqa: E402
from refusal_taxonomy_rerun import (  # noqa: E402
    MODEL_REGISTRY,
    PROMPT_TEMPLATES,
    load_model,
    load_samples,
    _model_input_device,
)

DEFAULT_INPUT = PROJECT_ROOT / "results" / "refusal_taxonomy" / "raw"
DEFAULT_OUTPUT = PROJECT_ROOT / "results" / "format_compliance_control"

PARSER = VulnerabilityOutputParser()

CHOICES = {
    "0": ["0", " 0"],
    "1": ["1", " 1"],
    "uncertain": ["unable to determine", " unable to determine"],
}


def production_label(text: str | None) -> int:
    if text is None:
        return -1
    try:
        return int(PARSER.parse(text))
    except OutputParserException:
        return -1


def prior_path(input_dir: Path, model: str, framing: str) -> Path:
    path = input_dir / f"{model}_{framing}_all_vulnerable.jsonl"
    if not path.exists():
        raise FileNotFoundError(path)
    return path


def load_prior_invalid_rows(path: Path, max_cases: int | None) -> list[dict]:
    rows: list[dict] = []
    with path.open() as fh:
        for line in fh:
            rec = json.loads(line)
            label = production_label(rec.get("raw_response"))
            if label != -1:
                continue
            rec = dict(rec)
            rec["prior_parser_label"] = label
            rows.append(rec)
            if max_cases is not None and len(rows) >= max_cases:
                break
    return rows


def score_completion(
    tokenizer,
    model,
    prompt: str,
    completion: str,
    max_prompt_tokens: int,
) -> tuple[float, float, int]:
    choice_ids = tokenizer(
        completion,
        add_special_tokens=False,
        return_tensors="pt",
    )["input_ids"][0]
    prompt_ids = tokenizer(
        prompt,
        add_special_tokens=True,
        truncation=True,
        max_length=max_prompt_tokens,
        return_tensors="pt",
    )["input_ids"][0]

    input_ids = torch.cat([prompt_ids, choice_ids], dim=0).unsqueeze(0)
    attention_mask = torch.ones_like(input_ids)
    labels = input_ids.clone()
    labels[:, : prompt_ids.numel()] = -100

    device = _model_input_device(model)
    input_ids = input_ids.to(device)
    attention_mask = attention_mask.to(device)
    labels = labels.to(device)

    with torch.no_grad():
        out = model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            labels=labels,
        )
    n_tokens = int(choice_ids.numel())
    total_logprob = -float(out.loss.detach().cpu()) * n_tokens
    avg_logprob = total_logprob / n_tokens if n_tokens else -math.inf
    return total_logprob, avg_logprob, n_tokens


def choose_label(tokenizer, model, prompt: str, max_prompt_tokens: int) -> dict:
    scores = []
    for label, variants in CHOICES.items():
        best = None
        for variant in variants:
            total, avg, n_tokens = score_completion(
                tokenizer,
                model,
                prompt,
                variant,
                max_prompt_tokens=max_prompt_tokens,
            )
            cand = {
                "label": label,
                "variant": variant,
                "total_logprob": total,
                "avg_logprob": avg,
                "tokens": n_tokens,
            }
            if best is None or cand["avg_logprob"] > best["avg_logprob"]:
                best = cand
        assert best is not None
        scores.append(best)
    scores.sort(key=lambda x: x["avg_logprob"], reverse=True)
    return {"chosen": scores[0], "scores": scores}


def write_summary(rows: list[dict], out_csv: Path) -> None:
    n = len(rows)
    forced_counts = {label: 0 for label in CHOICES}
    for row in rows:
        forced_counts[row["forced_label"]] += 1
    forced_parseable = forced_counts["0"] + forced_counts["1"]
    summary = {
        "n_prior_parser_invalid": n,
        "prior_parser_invalid_pct": 100.0 if n else 0.0,
        "forced_choice_invalid_n": 0,
        "forced_choice_invalid_pct": 0.0,
        "forced_choice_0": forced_counts["0"],
        "forced_choice_1": forced_counts["1"],
        "forced_choice_uncertain": forced_counts["uncertain"],
        "forced_choice_parseable_n": forced_parseable,
        "forced_choice_accuracy_on_vulnerable_pct": (
            100 * forced_counts["1"] / forced_parseable if forced_parseable else 0.0
        ),
    }
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(summary))
        writer.writeheader()
        writer.writerow(summary)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="llama", choices=sorted(MODEL_REGISTRY))
    p.add_argument("--framing", default="neutral", choices=sorted(PROMPT_TEMPLATES))
    p.add_argument("--dataset-scope", default="all_vulnerable")
    p.add_argument("--input-dir", default=str(DEFAULT_INPUT))
    p.add_argument("--output-dir", default=str(DEFAULT_OUTPUT))
    p.add_argument("--max-cases", type=int, default=None)
    p.add_argument("--max-prompt-tokens", type=int, default=4090)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--overwrite", action="store_true")
    args = p.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    out_jsonl = output_dir / f"{args.model}_{args.framing}_parser_invalid_forced_choice.jsonl"
    out_csv = output_dir / f"{args.model}_{args.framing}_parser_invalid_forced_choice_summary.csv"

    prior_rows = load_prior_invalid_rows(
        prior_path(input_dir, args.model, args.framing),
        max_cases=args.max_cases,
    )
    samples = load_samples(
        args.dataset_scope,
        db_path=None,
        num_samples=None,
        seed=42,
        shuffle=False,
    )
    sample_by_key = {s["record_key"]: s for s in samples}
    rows = [r for r in prior_rows if r["record_key"] in sample_by_key]

    print(
        f"[main] model={args.model} framing={args.framing} "
        f"prior_parser_invalid={len(rows)} output={out_jsonl}",
        flush=True,
    )
    if args.dry_run:
        for rec in rows:
            print(rec["record_key"])
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    if args.overwrite and out_jsonl.exists():
        out_jsonl.unlink()
    completed = set()
    if out_jsonl.exists():
        with out_jsonl.open() as fh:
            for line in fh:
                completed.add(json.loads(line)["record_key"])

    tokenizer, model = load_model(MODEL_REGISTRY[args.model])
    template = PROMPT_TEMPLATES[args.framing]
    written_rows: list[dict] = []
    if out_jsonl.exists():
        with out_jsonl.open() as fh:
            for line in fh:
                written_rows.append(json.loads(line))

    with out_jsonl.open("a") as fh:
        for idx, rec in enumerate(rows, start=1):
            key = rec["record_key"]
            if key in completed:
                continue
            sample = sample_by_key[key]
            prompt = template.format(code_block=sample["code_block"])
            result = choose_label(
                tokenizer,
                model,
                prompt,
                max_prompt_tokens=args.max_prompt_tokens,
            )
            chosen = result["chosen"]
            out = {
                "task": "format_compliance_control",
                "model": args.model,
                "hf_name": MODEL_REGISTRY[args.model],
                "framing": args.framing,
                "dataset_scope": args.dataset_scope,
                "record_key": key,
                "dataset": rec.get("dataset"),
                "sample_id": rec.get("sample_id"),
                "expected_label": 1,
                "prior_parser_label": rec["prior_parser_label"],
                "prior_raw_response": rec.get("raw_response"),
                "forced_label": chosen["label"],
                "forced_variant": chosen["variant"],
                "choice_scores": result["scores"],
            }
            fh.write(json.dumps(out, ensure_ascii=False) + "\n")
            fh.flush()
            written_rows.append(out)
            print(
                f"[score] {idx}/{len(rows)} {key} forced={chosen['label']} "
                f"avg_logprob={chosen['avg_logprob']:.4f}",
                flush=True,
            )

    write_summary(written_rows, out_csv)
    print(f"[ok] wrote {out_jsonl}", flush=True)
    print(f"[ok] wrote {out_csv}", flush=True)


if __name__ == "__main__":
    main()

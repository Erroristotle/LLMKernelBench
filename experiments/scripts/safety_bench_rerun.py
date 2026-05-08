"""Run the selected safety benchmark through one HF model and save raw output.

The first implemented benchmark is XSTest, using the prompts split from
``natolambert/xstest-v2-copy``. Output is raw JSONL so scoring can evolve
without re-running generation.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Iterable

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from refusal_taxonomy_rerun import (  # noqa: E402
    DEFAULT_OUTPUT_DIR,
    MODEL_REGISTRY,
    generate,
    load_model,
    read_completed_keys,
    shard_records,
)

DEFAULT_SAFETY_OUTPUT_DIR = PROJECT_ROOT / "results" / "safety_bench" / "xstest" / "raw"
HF_DATASET = "natolambert/xstest-v2-copy"


def _load_xstest_with_datasets(split: str) -> list[dict] | None:
    try:
        from datasets import load_dataset  # type: ignore
    except Exception:
        return None
    ds = load_dataset(HF_DATASET, split=split)
    records = []
    for idx, row in enumerate(ds):
        records.append(_normalise_xstest_row(idx, dict(row), split))
    return records


def _load_xstest_with_api(split: str) -> list[dict]:
    records = []
    offset = 0
    length = 100
    while True:
        resp = requests.get(
            "https://datasets-server.huggingface.co/rows",
            params={
                "dataset": HF_DATASET,
                "config": "default",
                "split": split,
                "offset": offset,
                "length": length,
            },
            timeout=60,
        )
        resp.raise_for_status()
        payload = resp.json()
        for item in payload.get("rows", []):
            records.append(
                _normalise_xstest_row(
                    int(item.get("row_idx", len(records))),
                    dict(item.get("row", {})),
                    split,
                )
            )
        total = int(payload.get("num_rows_total", len(records)))
        if len(records) >= total or not payload.get("rows"):
            break
        offset += length
    return records


def _normalise_xstest_row(idx: int, row: dict, split: str) -> dict:
    prompt = row.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError(f"XSTest row {idx} has no prompt")
    sample_id = str(row.get("id") or idx)
    return {
        "task": "xstest",
        "benchmark": "xstest",
        "split": split,
        "dataset": "xstest",
        "sample_id": sample_id,
        "record_key": f"xstest:{split}:{sample_id}",
        "xstest_type": row.get("type", ""),
        "final_label": row.get("final_label", ""),
        "annotation_1": row.get("annotation_1", ""),
        "annotation_2": row.get("annotation_2", ""),
        "agreement": row.get("agreement", None),
        "prompt": prompt,
    }


def load_xstest(split: str, num_samples: int | None) -> list[dict]:
    records = _load_xstest_with_datasets(split)
    if records is None:
        records = _load_xstest_with_api(split)
    if num_samples is not None:
        records = records[:num_samples]
    return records


def output_path_for(args: argparse.Namespace) -> Path:
    out_dir = Path(args.output_dir)
    if args.num_shards == 1:
        name = f"{args.model}_xstest_{args.split}.jsonl"
    else:
        name = (
            f"{args.model}_xstest_{args.split}"
            f"_shard{args.shard_index:02d}-of-{args.num_shards:02d}.jsonl"
        )
    return out_dir / name


def write_manifest(records: Iterable[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"[dry-run] wrote manifest {out_path}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, choices=list(MODEL_REGISTRY))
    parser.add_argument("--benchmark", default="xstest", choices=["xstest"])
    parser.add_argument("--split", default="prompts")
    parser.add_argument("--num-samples", type=int, default=None)
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--num-shards", type=int, default=1)
    parser.add_argument("--max-new-tokens", type=int, default=512)
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--greedy", action="store_true")
    parser.add_argument("--output-dir", default=str(DEFAULT_SAFETY_OUTPUT_DIR))
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--manifest-out", default=None)
    args = parser.parse_args()

    records_all = load_xstest(args.split, args.num_samples)
    records = shard_records(records_all, args.shard_index, args.num_shards)
    out_path = output_path_for(args)
    print(
        "[main] "
        f"model={args.model} benchmark=xstest split={args.split} "
        f"total_records={len(records_all)} shard={args.shard_index}/{args.num_shards} "
        f"shard_records={len(records)}",
        flush=True,
    )

    if args.dry_run:
        if args.manifest_out:
            write_manifest(records, Path(args.manifest_out))
        return

    out_path.parent.mkdir(parents=True, exist_ok=True)
    if args.overwrite and out_path.exists():
        out_path.unlink()
    completed = read_completed_keys(out_path)
    pending = [r for r in records if r["record_key"] not in completed]
    print(
        f"[main] output={out_path} completed={len(completed)} pending={len(pending)}",
        flush=True,
    )
    if not pending:
        print("[done] nothing to do", flush=True)
        return

    hf_name = MODEL_REGISTRY[args.model]
    tokenizer, model = load_model(hf_name)

    t0 = time.time()
    with out_path.open("a") as fh:
        for i, sample in enumerate(pending):
            try:
                raw = generate(
                    tokenizer,
                    model,
                    sample["prompt"],
                    max_new_tokens=args.max_new_tokens,
                    do_sample=not args.greedy,
                    temperature=args.temperature,
                )
            except Exception as e:
                raw = f"<<GENERATION_ERROR: {type(e).__name__}: {e}>>"
            rec = {
                **sample,
                "model": args.model,
                "hf_name": hf_name,
                "decoding": "greedy" if args.greedy else "sample",
                "temperature": None if args.greedy else args.temperature,
                "max_new_tokens": args.max_new_tokens,
                "prompt_chars": len(sample["prompt"]),
                "raw_response": raw,
                "response_chars": len(raw),
                "shard_index": args.shard_index,
                "num_shards": args.num_shards,
            }
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            elapsed = time.time() - t0
            print(
                f"[gen] {i + 1}/{len(pending)} key={sample['record_key']} "
                f"chars={len(raw)} elapsed={elapsed:.1f}s",
                flush=True,
            )

    print(f"[done] wrote {out_path}", flush=True)


if __name__ == "__main__":
    main()

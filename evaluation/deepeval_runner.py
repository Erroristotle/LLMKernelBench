import os
import sqlite3
from typing import List, Optional

from deepeval import evaluate
from deepeval.test_case import LLMTestCase
from deepeval.metrics import AnswerRelevancyMetric


def _label_to_text(label: Optional[int]) -> str:
    if label is None:
        return "unknown"
    if label == 1:
        return "vulnerable"
    if label == 0:
        return "not vulnerable"
    return "not sure"


def build_test_cases_from_sqlite(db_path: str) -> List[LLMTestCase]:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            COMMIT_HASH,
            VULNERABLE_CODE_BLOCK,
            IS_VULNERABLE_Vuln,
            PATCHED_CODE_BLOCK,
            IS_VULNERABLE_Patch
        FROM vulnerabilities
        WHERE VULNERABLE_CODE_BLOCK IS NOT NULL OR PATCHED_CODE_BLOCK IS NOT NULL
        """
    )
    rows = cur.fetchall()
    conn.close()

    cases: List[LLMTestCase] = []
    for commit_hash, vuln_code, vuln_label, patched_code, patch_label in rows:
        if vuln_code:
            cases.append(
                LLMTestCase(
                    input=f"Commit {commit_hash}: Is this code vulnerable?\n\n{vuln_code}",
                    actual_output=_label_to_text(vuln_label),
                )
            )
        if patched_code:
            cases.append(
                LLMTestCase(
                    input=f"Commit {commit_hash}: Is this code vulnerable?\n\n{patched_code}",
                    actual_output=_label_to_text(patch_label),
                )
            )
    return cases


def run_deepeval(db_path: str) -> None:
    # Metric uses an external LLM; requires OPENAI_API_KEY or configured backend
    metric = AnswerRelevancyMetric(threshold=0.5)
    test_cases = build_test_cases_from_sqlite(db_path)
    if not test_cases:
        print("No test cases found for DeepEval.")
        return
    evaluate(test_cases=test_cases, metrics=[metric])


if __name__ == "__main__":
    path = os.environ.get("DEEPEVAL_DB_PATH")
    if not path:
        raise SystemExit("Set DEEPEVAL_DB_PATH to the SQLite database path.")
    run_deepeval(path)



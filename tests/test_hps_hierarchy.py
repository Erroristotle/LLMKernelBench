from experiments.analysis.hps_score_analysis import (
    HIERARCHY_PATH,
    build_relationships,
    relationship_score,
)


def test_buffer_overflow_path_and_multi_parent_relations():
    parents, children, roots = build_relationships(HIERARCHY_PATH)

    assert "CWE-118" in children["CWE-664"]
    assert "CWE-119" in children["CWE-118"]
    assert "CWE-787" in children["CWE-119"]
    assert "CWE-121" in children["CWE-787"]
    assert parents["CWE-121"] == {"CWE-787", "CWE-788"}

    assert relationship_score(
        "CWE-121", "CWE-787", parents, children, roots
    ) == 0.7
    assert relationship_score(
        "CWE-121", "CWE-119", parents, children, roots
    ) == 0.4
    assert relationship_score(
        "CWE-120", "CWE-121", parents, children, roots
    ) == 0.6

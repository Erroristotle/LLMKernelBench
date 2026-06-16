"""Tests for classify_intent in audit_abstentions.py."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "experiments" / "analysis"))

from audit_abstentions import classify_intent


def test_starcoder2_comment_close_is_invalid():
    """'Not sure' inside a C comment followed by code — not a real abstention."""
    text = 'Not sure\n*/\n\n#include "stdafx.h"\n\nint main() { return 0; }'
    intent, _ = classify_intent(text)
    assert intent == "invalid_or_indeterminate"


def test_starcoder2_comment_close_variant_is_invalid():
    text = " not sure\n*/\n\n/*\n\n# CVE-2016-7219\nFile: something.py\n"
    intent, _ = classify_intent(text)
    assert intent == "invalid_or_indeterminate"


def test_codellama_html_hallucination_is_invalid():
    """'not sure' followed by HTML/JS garbage — not a real abstention."""
    text = (
        "not sure\n\n\n"
        "####### Fixed it up\n"
        '<div id="disqus_thread"></div>\n'
        "<script>\n(function() { var d = document; })();\n</script>\n"
    )
    intent, _ = classify_intent(text)
    assert intent == "invalid_or_indeterminate"


def test_genuine_verbose_abstention_with_prose_explanation():
    """'not sure' + natural-language explanation must still be verbose_abstention."""
    text = (
        "not sure\n\n"
        "Explanation:\n"
        "There is nothing here that would cause a KASLR bypass. "
        "This function first copies every element of the vcpu->arch.db array."
    )
    intent, _ = classify_intent(text)
    assert intent == "verbose_abstention"


def test_clean_abstention_bare_not_sure():
    intent, fmt = classify_intent("not sure")
    assert intent == "clean_abstention"
    assert fmt is True


def test_clean_abstention_bare_minus_one():
    intent, fmt = classify_intent("-1")
    assert intent == "clean_abstention"
    assert fmt is True


def test_contradictory_abstention_and_binary_verdict_is_invalid():
    intent, fmt = classify_intent("not sure\nFinal answer: 1")
    assert intent == "invalid_or_indeterminate"
    assert fmt is False


def test_clean_binary_labels():
    assert classify_intent("0") == ("binary", True)
    assert classify_intent("1") == ("binary", True)

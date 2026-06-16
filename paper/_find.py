from pypdf import PdfReader
r = PdfReader("main.pdf")
phrases = {
    "hps_validation": "metric assumes that hierarchical distance",
    "hps_validation2": "289/2,077",
    "ranking_rationale": "ranking formulation instead",
    "ranking_rationale2": "many with fewer than 10 examples",
    "deployment_cost_p": "1,000 Level",
    "securefalcon_results": "stand in sharp contrast to supervised",
}
for label, ph in phrases.items():
    pages = []
    for i, pg in enumerate(r.pages):
        t = (pg.extract_text() or "")
        if ph.lower() in t.lower():
            pages.append(i + 1)
    print(f"{label!r}: pages {pages}")

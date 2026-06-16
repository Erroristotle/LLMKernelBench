from pypdf import PdfReader
r = PdfReader("main.pdf")
print("PAGES=", len(r.pages))
print("\n=== PAGE 15 TAIL (appendix) ===")
print((r.pages[14].extract_text() or "")[-1100:])

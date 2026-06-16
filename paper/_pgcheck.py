from pypdf import PdfReader
r = PdfReader("main.pdf")
print("PAGES=", len(r.pages))
for p in range(13, len(r.pages)):
    t = r.pages[p].extract_text() or ""
    print(f"PAGE {p+1}: {len(t)} chars")
print("\n=== TAIL OF PAGE 15 ===")
print((r.pages[14].extract_text() or "")[-600:])

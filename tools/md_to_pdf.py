"""Markdown -> PDF (headless Chrome) для читабельного реестра угроз. Это НЕ экспорт Threat Dragon.
Запуск: python3 tools/md_to_pdf.py threat-model/threat-register.md threat-model/threat-register.pdf [/usr/bin/google-chrome]
"""
import sys
from pathlib import Path

import markdown
from playwright.sync_api import sync_playwright

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
chrome = sys.argv[3] if len(sys.argv) > 3 else None
body = markdown.markdown(src.read_text(encoding="utf-8"), extensions=["tables"])
html = f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>{src.stem}</title><style>
@page {{ size: A4 landscape; margin: 12mm 10mm; }}
body {{ font-family: "DejaVu Sans", Arial, sans-serif; font-size: 10.5pt; line-height: 1.35; color: #111; }}
h1 {{ font-size: 18pt; }} h2 {{ font-size: 14pt; margin-top: 18pt; break-after: avoid; }}
h3, h4 {{ font-size: 11.5pt; margin: 12pt 0 4pt; break-after: avoid; }}
table {{ border-collapse: collapse; width: 100%; margin: 6pt 0; font-size: 9.5pt; }}
th, td {{ border: 1px solid #999; padding: 3pt 5pt; vertical-align: top; text-align: left; }}
th {{ background: #eee; }} tr {{ break-inside: avoid; }}
blockquote {{ border-left: 3px solid #c33; margin: 6pt 0; padding: 2pt 8pt; background: #fafafa; }}
code {{ font-size: 9pt; }}
</style></head><body>{body}</body></html>"""
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=chrome, args=["--no-sandbox"]) if chrome else p.chromium.launch()
    pg = b.new_page()
    pg.set_content(html, wait_until="load")
    pg.pdf(path=str(dst), prefer_css_page_size=True, print_background=True)
    b.close()
print("written", dst)

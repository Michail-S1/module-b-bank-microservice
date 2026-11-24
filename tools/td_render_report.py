"""Автоматизирует OWASP Threat Dragon (web, v2.6.2): импорт модели, экспорт DFD в PNG/SVG
и печать отчёта (Report -> Печать) в PDF. Эквивалент ручных действий в UI.
Требования: запущенный Threat Dragon (td.vue: `npx vue-cli-service serve --port 8088`),
pip install playwright, Chrome/Chromium.
Запуск: python3 tools/td_render_report.py http://localhost:8088 /usr/bin/google-chrome [out.pdf]
"""
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
MODEL = ROOT / "threat-model" / "bank-microservice.threatdragon.json"
OUTDIR = ROOT / "threat-model"
TD = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8088"
CHROME = sys.argv[2] if len(sys.argv) > 2 else None
OUT_PDF = Path(sys.argv[3]) if len(sys.argv) > 3 else OUTDIR / "threat-model-report.pdf"
# Параметры печати — те же, что в диалоге печати браузера (кнопка «Печать» отчёта Threat Dragon):
# A4, альбомная ориентация (шире столбцы таблиц угроз), масштаб 90 % (при 100 % диаграмма не помещается
# на альбомную страницу и Chrome добавляет пустую страницу), с фоном.
# Bootstrap 4 в Threat Dragon задаёт @page { size: a3 } для печати и перекрывает параметры ориентации,
# поэтому перед печатью добавляется правило @page A4 landscape (аналог выбора «Альбомная» в диалоге печати).
PAGE_CSS = "@page { size: A4 landscape; }"
PRINT = dict(prefer_css_page_size=True, scale=0.9, print_background=True,
             margin={"top": "10mm", "bottom": "10mm", "left": "8mm", "right": "8mm"})

with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"]) if CHROME else p.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1600, "height": 1000}, accept_downloads=True)
    pg = ctx.new_page()
    pg.goto(TD + "/", wait_until="networkidle")
    pg.click("text=English")
    pg.click("text=Русский")
    pg.click("#local-login-btn")
    pg.wait_for_timeout(800)
    pg.goto(TD + "/#/local/threatmodel/import", wait_until="networkidle")
    pg.fill("#json-input", MODEL.read_text(encoding="utf-8"))
    pg.click("#td-import-btn")
    pg.wait_for_timeout(1500)

    # DFD: редактор диаграммы -> Экспортировать -> PNG / SVG
    pg.click("text=DFD: Bank Microservice (уровень 1)")
    pg.wait_for_timeout(2500)
    for fmt, fname in (("PNG", "dfd.png"), ("SVG", "dfd.svg")):
        pg.click("text=Экспортировать")
        with pg.expect_download() as dl:
            pg.click(f"a:has-text('{fmt}'), button:has-text('{fmt}')")
        dl.value.save_as(OUTDIR / fname)
    pg.go_back()
    pg.wait_for_timeout(1200)

    # Отчёт: включаем свойства элементов, печатаем в PDF (как кнопка «Печать» -> «Сохранить как PDF»)
    pg.click("#td-report-btn")
    pg.wait_for_timeout(3000)
    if not pg.is_checked("#show_attributes"):
        pg.click("label[for=show_attributes]")
        pg.wait_for_timeout(800)
    pg.add_style_tag(content=PAGE_CSS)
    pg.emulate_media(media="print")
    pg.pdf(path=str(OUT_PDF), **PRINT)
    pg.emulate_media(media="screen")
    pg.screenshot(path=str(OUTDIR / "report-preview.png"), full_page=False)
    browser.close()
print("ok:", [f.name for f in OUTDIR.iterdir()])

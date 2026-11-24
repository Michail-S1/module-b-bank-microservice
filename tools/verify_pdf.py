"""Проверка PDF: открываются, число и размер страниц, нет пустых страниц, есть ключевые формулировки,
содержимое PDF Threat Dragon соответствует текущей модели JSON. Запуск из корня комплекта:
    python3 tools/verify_pdf.py
Нужны pypdf и poppler (pdftoppm) для оценки заполненности страниц.
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parent.parent
fails = []


def check(cond, msg):
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def ink_ratio(png):
    """Доля не-белых пикселей (PPM через pdftoppm -> читаем как P6)."""
    data = png.read_bytes()
    # формат P6: заголовок из 3 строк, затем RGB
    parts = data.split(b"\n", 3)
    w, h = map(int, parts[1].split())
    px = parts[3]
    dark = sum(1 for i in range(0, len(px), 3 * 7) if px[i] < 235 or px[i + 1] < 235 or px[i + 2] < 235)
    return dark / (len(px) / (3 * 7))


def norm(s):
    # Chrome подставляет в подмножества шрифтов глифы из Private Use Area для «-», «(», «)», «:» и т. п.,
    # поэтому сравнение идёт только по буквам и цифрам.
    return re.sub(r"[^0-9A-Za-zА-Яа-яЁё]+", "", s)


model = json.loads((ROOT / "threat-model/bank-microservice.threatdragon.json").read_text(encoding="utf-8"))
threats = [t for c in model["detail"]["diagrams"][0]["cells"] for t in c["data"].get("threats", [])]

for name, landscape in (("threat-model/threat-model-report.pdf", True), ("threat-model/threat-register.pdf", True)):
    path = ROOT / name
    r = PdfReader(str(path))
    n = len(r.pages)
    check(n > 0, f"{name}: открывается, страниц {n}")
    sizes = {(round(float(p.mediabox.width)), round(float(p.mediabox.height))) for p in r.pages}
    check(all(w > h for w, h in sizes) == landscape, f"{name}: размер страниц {sorted(sizes)} (A4 альбомная)")
    text = norm(" ".join(p.extract_text() or "" for p in r.pages))
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["pdftoppm", "-r", "20", str(path), f"{tmp}/p"], check=True, capture_output=True)
        ratios = [ink_ratio(p) for p in sorted(Path(tmp).glob("p-*.ppm"))]
    low = [i + 1 for i, x in enumerate(ratios) if x < 0.002]
    sparse = [i + 1 for i, x in enumerate(ratios) if 0.002 <= x < 0.01]
    check(not low, f"{name}: пустых страниц нет (доля «чернил» по страницам: min {min(ratios):.4f})")
    if sparse:
        print(f"     малозаполненные страницы (вёрстка источника): {sparse}")
    if "threat-model-report" in name:
        # заголовки карточек в PDF Threat Dragon переносятся по словам — сверяем первые слова каждой карточки
        missing = [t["number"] for t in threats if norm(t["title"])[:25] not in text]
        check(not missing, f"{name}: все {len(threats)} карточки модели присутствуют (по началу заголовка); нет: {missing}")
        for s in ("Потенциальная регрессия к SQL Injection", "Не подтверждены механизмы резервного",
                  "необеспеченные зачисления", "[RC-1]", "OWASP Threat Dragon",
                  "Фактическое шифрование соединения не проверено",            # ИСПР-11
                  "существование получателя не доказывают",                     # ИСПР-12
                  "SQL Injection в этом запросе не подтверждена",               # ИСПР-05
                  "исходящие операции счетов выбранного владельца"):            # ИСПР-13
            check(norm(s) in text or s == "OWASP Threat Dragon" and r.metadata.get("/Title") == "OWASP Threat Dragon",
                  f"{name}: содержит «{s}»")
        check(norm("деньги создаются") not in text and norm("из воздуха") not in text, f"{name}: нет формулировки «из воздуха»")
        check(norm("канал не шифруется") not in text, f"{name}: нет утверждения «канал не шифруется» (ИСПР-11)")
        check(norm("Insufficient funds' выдаёт существование") not in text, f"{name}: 400 не служит доказательством оракула (ИСПР-12)")
    else:
        check(norm("Это не экспорт OWASP Threat Dragon") in text, f"{name}: помечен как не экспорт Threat Dragon")
        check(all(norm(f"{t['number']}. {t['title']}") in text for t in threats), f"{name}: все {len(threats)} карточек описаны")

print("\nИТОГ:", "все проверки пройдены" if not fails else f"{len(fails)} проверок не прошли")
sys.exit(1 if fails else 0)

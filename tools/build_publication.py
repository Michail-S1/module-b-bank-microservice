"""Собирает публикуемую копию комплекта (ИСПР-14): все файлы по тем же относительным путям + index.html
(отчёт и перечень файлов) и HTML-версии Markdown-документов. Ссылки на пути в `code` ведут к файлам.
Запуск из корня комплекта: python3 tools/build_publication.py <out_dir> <zip_sha256>
"""
import html
import re
import shutil
import sys
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(sys.argv[1])
ZIP_SHA = sys.argv[2] if len(sys.argv) > 2 else ""
SKIP = {".community-rules", "__pycache__"}
FILES = sorted(p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
               if p.is_file() and not SKIP & set(p.relative_to(ROOT).parts) and p.name != ".gitignore")
MD_PAGES = {"REPORT.md": "index.html", "AUDIT_FIXES.md": "AUDIT_FIXES.html", "README.md": "README.html",
            "evidence/README.md": "evidence/README.html", "threat-model/threat-register.md": "threat-model/threat-register.html"}
# Хостинг артефактов отдаёт только известные типы; .yml/.log/.py/.sh публикуются с суффиксом .txt (содержимое то же)
SERVED = {".html", ".css", ".js", ".json", ".md", ".txt", ".csv", ".png", ".svg", ".pdf", ".xml"}


def pub(rel):
    """Опубликованное имя файла: тот же путь; для неподдерживаемых расширений добавляется .txt."""
    return rel if Path(rel).suffix in SERVED else rel + ".txt"


SEARCH = ["", "evidence/", "microservice/", "microservice/app/", "semgrep/", "threat-model/", "tools/", "evidence/scripts/"]

CSS = """
/* VOICE: спокойный технический документ для проверяющего
   IDEA: папка дела — обложка с реестром вложений, затем сам отчёт
   PICTURE: реестр ключевых вложений крупными строками в первом экране
   COLOUR/TYPE: Atlas plate — глубокое море #0a2540, небесный #8fd3ff, белый, сигнальный розовый #ff5c8a; Hanken Grotesk
   LAYOUT: шапка-обложка, реестр вложений, затем отчёт в одну колонку */
:root{color-scheme:dark;--bg:#0a2540;--ink:#f4f8fc;--mute:#b9c8d8;--sky:#8fd3ff;--pink:#ff5c8a;--line:rgba(143,211,255,.22)}
:root[data-theme=light],:root[data-theme=dark]{color-scheme:dark}
*{box-sizing:border-box;min-width:0}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 "Hanken Grotesk",system-ui,sans-serif;overflow-x:clip}
.band{padding:clamp(24px,4vw,56px) max(5vw,16px)}.wrap{max-width:1120px;margin:0 auto}
header.band{border-bottom:1px solid var(--line)}
h1{font-weight:300;font-size:clamp(32px,5vw,52px);line-height:1.05;margin:0 0 14px;text-wrap:balance}
h2{font-size:26px;line-height:1.2;margin:40px 0 12px;font-weight:600}h3,h4{font-size:19px;margin:26px 0 8px;font-weight:600}
p,li{max-width:78ch}a{color:var(--sky)}a:hover{color:#fff}.mute{color:var(--mute);font-size:14px}
.key{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:2px;margin:24px 0 6px}
.key a{display:block;padding:14px 16px;background:rgba(143,211,255,.08);text-decoration:none;border-left:3px solid var(--sky)}
.key a b{display:block;color:#fff;font-weight:600}.key a span{color:var(--mute);font-size:14px}
.key a.main{border-left-color:var(--pink)}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:14px}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{background:rgba(143,211,255,.1)}
.scroll{overflow-x:auto}code{font:13.5px/1.4 ui-monospace,Menlo,monospace;overflow-wrap:anywhere;color:#d9f0ff}
pre{overflow-x:auto;background:rgba(0,0,0,.28);padding:12px;border:1px solid var(--line)}
blockquote{margin:12px 0;padding:6px 14px;border-left:3px solid var(--pink);background:rgba(255,92,138,.07)}
img{max-width:100%;background:#fff;border-radius:4px}
details{margin:18px 0}summary{cursor:pointer;color:var(--sky);min-height:44px;display:flex;align-items:center}
@media(max-width:600px){table{font-size:13px}}
"""


def link_code(body: str, page_dir: str) -> str:
    """Оборачивает <code>путь[:строки]</code> в ссылку на файл комплекта, если файл существует."""
    up = "../" * page_dir.count("/") if page_dir else ""

    def repl(m):
        txt = html.unescape(m.group(1))
        cand = re.sub(r":[0-9][0-9,\- ]*$", "", txt.split(" ")[0]).rstrip(",.;")
        if "/" not in cand and "." not in cand:
            return m.group(0)
        for pre in SEARCH:
            target = pre + cand.lstrip("./")
            if target in FILES:
                target = MD_PAGES.get(target, pub(target))  # Markdown — на HTML-версию; прочее — на опубликованное имя
                return f'<a href="{up}{target}"><code>{m.group(1)}</code></a>'
        return m.group(0)

    return re.sub(r"<code>([^<]{3,140})</code>", repl, body)


def page(title, body, page_dir=""):
    up = "../" * page_dir.count("/") if page_dir else ""
    return f"""<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{html.escape(title)}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Hanken+Grotesk:wght@300;400;600&display=swap">
<style>{CSS}</style></head><body>
<header class="band"><div class="wrap"><p class="mute"><a href="{up}index.html">Модуль B — комплект к сдаче</a></p>
<h1>{html.escape(title)}</h1></div></header><main class="band"><div class="wrap">{body}</div></main></body></html>"""


def render_md(rel):
    text = (ROOT / rel).read_text(encoding="utf-8")
    body = markdown.markdown(text, extensions=["tables", "fenced_code"])
    body = re.sub(r"<table>", '<div class="scroll"><table>', body).replace("</table>", "</table></div>")
    page_rel = MD_PAGES[rel]
    page_dir = page_rel.rsplit("/", 1)[0] + "/" if "/" in page_rel else ""
    # ссылки [..](x.md) -> html-версии; относительные пути от каталога исходного .md
    for md, h in MD_PAGES.items():
        src_dir = rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""
        if md.startswith(src_dir):
            body = body.replace(f'href="{md[len(src_dir):]}"', f'href="{h[len(src_dir):]}"')
    body = re.sub(r"<h1>.*?</h1>", "", body, count=1)
    title = re.search(r"^# (.+)$", text, re.M).group(1)
    return title, link_code(body, page_dir), page_dir


if OUT.exists():
    shutil.rmtree(OUT)
for rel in FILES:
    (OUT / rel).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / rel, OUT / pub(rel))

KEY = [("REPORT.md", "Основной отчёт", "DFD, топ-3 угрозы, контрмеры, SAST, SDLC — ниже на этой странице", "main"),
       ("threat-model/threat-model-report.pdf", "Экспорт OWASP Threat Dragon (PDF)", "Threat Dragon 2.6.2, A4 альбомная, 15 стр.", "main"),
       ("semgrep/semgrep-raw.json", "Semgrep JSON — исходный", "вывод semgrep --json, 25 находок, без изменений", "main"),
       ("semgrep/semgrep-results.json", "Semgrep JSON — итоговый", "25 автоматических + 6 MANUAL (в т.ч. 2 IDOR), триаж", "main"),
       ("threat-model/bank-microservice.threatdragon.json", "Модель Threat Dragon (JSON)", "DFD + 22 карточки STRIDE", ""),
       ("threat-model/threat-register.html", "Реестр угроз", "корневые причины, карточки, критерии эффективности (не экспорт TD)", ""),
       ("semgrep/custom-rules.yml", "Кастомные правила Semgrep", "16 правил", ""),
       ("AUDIT_FIXES.html", "Исправления по аудитам", "ИСПР-01…14", ""),
       ("evidence/README.html", "Доказательства", "логи стенда, SCA, проверки комплекта", "")]
key_html = "".join(
    f'<a class="{c}" href="{h if h.endswith(".html") or h.startswith("#") else pub(h)}"><b>{html.escape(t)}</b><span>{html.escape(d)}</span></a>'
    for h, t, d, c in [(k if k != "REPORT.md" else "#report", t, d, c) for k, t, d, c in KEY])
rows = "".join(f'<tr><td><a href="{pub(r)}"><code>{html.escape(r)}</code></a></td><td style="text-align:right">'
               f'{(ROOT / r).stat().st_size:,}</td></tr>'.replace(",", " ") for r in FILES)
title, report_body, _ = render_md("REPORT.md")
index_body = (f'<p>Банковский микросервис: модель угроз, контрмеры (рекомендации), SAST Semgrep с ручным IDOR, '
              f'процесс управления уязвимостями. Все файлы опубликованы по тем же относительным путям, что в архиве '
              f'<code>module-B-submission-v3.zip</code>' + (f' (SHA-256 <code>{ZIP_SHA}</code>)' if ZIP_SHA else '') + '. '
              f'Файлы .yml, .log, .py и .sh хостинг отдаёт только как текст, поэтому они опубликованы с добавленным '
              f'суффиксом <code>.txt</code>; содержимое не изменено.</p>'
              f'<nav class="key">{key_html}</nav>'
              f'<details><summary>Все файлы комплекта ({len(FILES)})</summary><div class="scroll"><table>'
              f'<tr><th>Путь</th><th>Байт</th></tr>{rows}</table></div></details>'
              f'<section id="report"><h2>{html.escape(title)}</h2>{report_body}</section>')
(OUT / "index.html").write_text(page("Модуль B — банковский микросервис", index_body), encoding="utf-8")
for rel, h in MD_PAGES.items():
    if rel == "REPORT.md":
        continue
    t, b, d = render_md(rel)
    (OUT / h).write_text(page(t, b, d), encoding="utf-8")
print(f"{OUT}: {len(FILES)} файлов комплекта + {len(MD_PAGES)} HTML")

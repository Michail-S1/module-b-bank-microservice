"""Проверка документов комплекта: синтаксис JSON/YAML, разбор Markdown, относительные ссылки и упомянутые пути.
Запуск из корня комплекта: python3 tools/verify_docs.py
"""
import json
import re
import sys
from pathlib import Path

import markdown
import yaml

ROOT = Path(__file__).resolve().parent.parent
SKIP = {".community-rules", "__pycache__"}
EXTERNAL = {"Jobs/SAST.gitlab-ci.yml"}  # имя шаблона GitLab, а не файл комплекта
fails = []


def check(cond, msg):
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


files = [p for p in ROOT.rglob("*") if p.is_file() and not SKIP & set(p.relative_to(ROOT).parts)]
for p in files:
    rel = p.relative_to(ROOT)
    if p.suffix in (".json", ".sarif"):
        try:
            json.loads(p.read_text(encoding="utf-8")); ok = True
        except Exception as e:  # noqa: BLE001
            ok = False; print("     ", e)
        check(ok, f"JSON: {rel}")
    elif p.suffix in (".yml", ".yaml"):
        try:
            yaml.safe_load(p.read_text(encoding="utf-8")); ok = True
        except Exception as e:  # noqa: BLE001
            ok = False; print("     ", e)
        check(ok, f"YAML: {rel}")

PATH_RE = re.compile(r"`([A-Za-z0-9_./*-]+/[A-Za-z0-9_.*-]+\.(?:md|json|log|py|sh|yml|txt|pdf|png|svg|sarif))`")
for md in [p for p in files if p.suffix == ".md"]:
    text = md.read_text(encoding="utf-8")
    markdown.markdown(text, extensions=["tables"])
    check(text.count("```") % 2 == 0, f"Markdown: {md.relative_to(ROOT)} — блоки кода закрыты")
    for target in re.findall(r"\]\(([^)#\s]+)\)", text):
        if target.startswith(("http://", "https://")):
            continue
        check((md.parent / target).exists(), f"ссылка {md.relative_to(ROOT)} -> {target}")
    for ref in sorted(set(PATH_RE.findall(text)) - EXTERNAL):
        if "*" in ref:
            ok = any(ROOT.glob(ref)) or any((ROOT / "evidence").glob(ref.split("/", 1)[-1]))
        else:
            cands = [md.parent / ref, ROOT / ref, ROOT / "microservice" / ref, ROOT / "evidence" / ref]
            ok = any(c.exists() for c in cands)
        check(ok, f"путь {md.relative_to(ROOT)}: `{ref}`")

print("\nИТОГ:", "все проверки пройдены" if not fails else f"{len(fails)} проверок не прошли")
sys.exit(1 if fails else 0)

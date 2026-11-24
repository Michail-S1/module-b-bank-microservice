"""Проверка согласованности результатов Semgrep. Запуск из корня комплекта:
    python3 tools/verify_semgrep.py [semgrep/rerun/semgrep-raw-rerun.json]
Проверяет:
  1) исходный raw = 25 автоматических находок, итоговый = raw + 6 ручных (engine_kind MANUAL);
  2) автоматическая часть итогового JSON совпадает с raw (check_id, path, строки);
  3) у каждой находки есть CWE и триаж, файл и строки существуют, `lines` ручных находок совпадает с кодом;
  4) повторный прогон (если передан) даёт тот же набор (check_id, path, start, end).
Код выхода 0 — все проверки прошли.
"""
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
raw = json.loads((ROOT / "semgrep/semgrep-raw.json").read_text(encoding="utf-8"))
res = json.loads((ROOT / "semgrep/semgrep-results.json").read_text(encoding="utf-8"))
key = lambda r: (r["check_id"], r["path"], r["start"]["line"], r["end"]["line"])
fails = []


def check(cond, msg):
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


auto = [r for r in res["results"] if r["extra"].get("engine_kind") != "MANUAL"]
manual = [r for r in res["results"] if r["extra"].get("engine_kind") == "MANUAL"]
check(len(raw["results"]) == 25, f"raw: {len(raw['results'])} автоматических находок (ожидалось 25)")
check(len(auto) == 25 and sorted(map(key, auto)) == sorted(map(key, raw["results"])),
      f"итоговый JSON: автоматическая часть ({len(auto)}) совпадает с raw")
check(len(manual) == 6, f"итоговый JSON: {len(manual)} ручных находок с engine_kind=MANUAL (ожидалось 6)")
check(all(r["check_id"].startswith("manual.") for r in manual), "все ручные check_id начинаются с manual.")
check(not any(r["check_id"].startswith("manual.") for r in auto), "нет manual.* среди автоматических")
idor = [r["check_id"] for r in manual if r["check_id"].startswith("manual.idor")]
check(len(idor) == 2, f"IDOR в итоговом JSON: {idor}")

for r in res["results"]:
    md = r["extra"].get("metadata", {})
    p = ROOT / r["path"]
    ok_file = p.is_file()
    lines = p.read_text(encoding="utf-8").splitlines() if ok_file else []
    ok_lines = ok_file and 1 <= r["start"]["line"] <= r["end"]["line"] <= len(lines)
    ok_cwe = bool(md.get("cwe"))
    ok_tri = bool(md.get("triage", {}).get("status"))
    ok_snip = True
    if r["extra"].get("engine_kind") == "MANUAL" and ok_lines:
        ok_snip = r["extra"]["lines"] == "\n".join(lines[r["start"]["line"] - 1:r["end"]["line"]])
    if not (ok_file and ok_lines and ok_cwe and ok_tri and ok_snip):
        check(False, f"{r['check_id']} {r['path']}:{r['start']['line']} file={ok_file} lines={ok_lines} "
                     f"cwe={ok_cwe} triage={ok_tri} snippet={ok_snip}")
check(True, f"пути/строки/CWE/триаж проверены у {len(res['results'])} находок")

sev = Counter(r["extra"]["severity"] for r in res["results"])
tri = Counter(r["extra"]["metadata"]["triage"]["status"] for r in res["results"])
print("severity:", dict(sev))
print("triage:", dict(tri))

if len(sys.argv) > 1:
    rerun = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    check(len(rerun["results"]) == len(raw["results"]),
          f"повторный прогон: {len(rerun['results'])} находок (исходно {len(raw['results'])})")
    check(sorted(map(key, rerun["results"])) == sorted(map(key, raw["results"])),
          "повторный прогон: тот же набор (check_id, path, start, end)")
    check(rerun.get("version") == raw.get("version"), f"версия Semgrep {rerun.get('version')} = {raw.get('version')}")
    check(not rerun["errors"], f"ошибок сканирования: {len(rerun['errors'])}")

print("\nИТОГ:", "все проверки пройдены" if not fails else f"{len(fails)} проверок не прошли")
sys.exit(1 if fails else 0)

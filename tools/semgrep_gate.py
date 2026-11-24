"""Блокирующий gate по результатам Semgrep JSON: код выхода 1, если есть находки с severity из списка.
Запуск: python3 tools/semgrep_gate.py semgrep.json [ERROR,WARNING]
Находки, подавленные `# nosemgrep` с обоснованием, Semgrep помечает is_ignored и сюда не считаются.
"""
import json
import sys

path = sys.argv[1]
block = set((sys.argv[2] if len(sys.argv) > 2 else "ERROR").split(","))
results = json.load(open(path, encoding="utf-8"))["results"]
hits = [r for r in results if r["extra"]["severity"] in block and not r["extra"].get("is_ignored")]
for r in hits:
    print(f'{r["extra"]["severity"]:7} {r["check_id"]}  {r["path"]}:{r["start"]["line"]}')
print(f"gate: {len(hits)} находок уровня {sorted(block)} из {len(results)}")
sys.exit(1 if hits else 0)

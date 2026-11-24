"""Сливает сырой вывод Semgrep с ручными находками и разметкой триажа.

Вход:  semgrep/semgrep-raw.json (вывод `semgrep --json`, не изменяется)
       semgrep/manual-findings.json (ручные находки, в т.ч. IDOR)
Выход: semgrep/semgrep-results.json — тот же формат Semgrep JSON, ручные находки
       добавлены в results[] с extra.engine_kind = "MANUAL", у каждой находки
       extra.metadata.triage = {status, evidence}.
Запуск из корня репозитория: python3 tools/merge_findings.py
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "semgrep" / "semgrep-raw.json"
MANUAL = ROOT / "semgrep" / "manual-findings.json"
OUT = ROOT / "semgrep" / "semgrep-results.json"

# Триаж автоматических находок: (rule suffix, line) -> (status, evidence)
TRIAGE = {
    ("bank.balance-check-without-row-lock", 22): ("confirmed", "evidence/race_check.log: в 4 из 10 раундов по 30 параллельных переводов баланс отправителя ушёл в минус (до -30000); доп. прогон evidence/race_invariant_check.log: 8 из 10, сумма остатков по всем счетам в каждом раунде не менялась"),
    ("bank.existence-oracle-404", 24): ("true_positive_low", "счёт списания: ветка 404 'From account not found' (crud.py:23-24) при штатной работе недостижима — _must_own_account (crud.py:5-13) уже требует строки accounts с этим id и владельцем, иначе 403 (dynamic_checks.log:21-22, шаг 3). 404 возможен только при удалении счёта между проверками; оракула существования счёта списания нет"),
    ("bank.existence-oracle-404", 30): ("confirmed", "основание — код: после проверки баланса (crud.py:22-26) отсутствующий получатель даёт 404 'To account not found' (crud.py:28-30), существующий — операция продолжается (crud.py:32-38). Наблюдения стенда: счёт списания 2, сумма 1: получатель 999 -> 404 (dynamic_checks.log:35-36, шаг 5); получатель 1 -> HTTP 200 (dynamic_checks.log:50-51, шаг 7b; другой шаг стенда). Строки 37-38 (400 'Insufficient funds') показывают ветку нехватки средств, которая срабатывает до проверки получателя, и доказательством существования получателя не являются. Ограничение: при существующем получателе проба выполняет реальный перевод"),
    ("bank.cache-hit-returns-empty", 46): ("confirmed", "evidence/dynamic_checks.log, шаг 7: SET tx:1:20: x -> история пуста"),
    ("bank.dynamic-sql-fstring", 61): ("false_positive_exploitability", "основание — путь данных по коду: в f-строку подставляется только номер плейсхолдера ${i} (int, формируется в функции), значение search добавляется в params (crud.py:62) и передаётся conn.fetch(sql, *params) (crud.py:66). Иллюстрация: dynamic_checks.log:25-26 — тело ответа [] за ~4 мс. Оставлено как регрессионный риск (карточка #5)"),
    ("bank.dynamic-sql-fstring", 64): ("false_positive_exploitability", "аналогично строке 61: в строку попадает номер плейсхолдера, значение limit добавляется в params (crud.py:65) и валидировано Query(ge=1, le=100) (main.py:21)"),
    ("asyncpg-sqli", 66): ("false_positive_exploitability", "правило реагирует на SQL, собранный форматированием; значения пользователя передаются связуемыми параметрами conn.fetch(sql, *params) (crud.py:66). Наблюдения: dynamic_checks.log:25-26 — payload ' OR '1'='1 -> тело [] за ~4 мс; строки 27-28 — payload с pg_sleep(3) -> HTTP 200 за ~2,4 мс, тело ответа не сохранено. Основание вывода — путь данных по коду, а не время ответа"),
    ("bank.like-wildcard-not-escaped", 62): ("confirmed", "search=_ совпадает с любым id, то есть возвращает все строки той же выборки — исходящие операции счетов владельца из X-User-Id, не более limit (crud.py:52-65); за пределы владельца wildcard выборку не расширяет. dynamic_checks.log:30-32 (шаг 4b): для пользователя 1 возвращена его единственная операция"),
    ("bank.asyncpg-pool-without-tls", 9): ("true_positive_hardening", "подтверждено только: в конфигурации сервиса явно не задано требование TLS с проверкой имени сервера — create_pool без ssl= (db.py:9), в DSN нет sslmode (docker-compose.yml:23). asyncpg 0.29.0 при этом для TCP использует sslmode=prefer (asyncpg/connect_utils.py:489-492, тег v0.29.0): TLS, если его поддерживает сервер, без проверки сертификата. Фактическое шифрование соединения не проверено. Утверждение extra.message об открытом тексте — формулировка правила на момент сканирования; правило с тех пор переформулировано, повторный запуск обновлённых правил не выполнялся. Рекомендация: sslmode=verify-full с проверкой сертификата сервера"),
    ("bank.fastapi-docs-exposed", 7): ("confirmed", "evidence/dynamic_checks.log, шаг 10: /docs и /openapi.json -> 200"),
    ("bank.amount-without-upper-bound", 6): ("true_positive_low", "шаг 6: переполнение BIGINT не достижимо (отсекается проверкой баланса); остаётся отсутствие лимитов операции"),
    ("bank.identity-from-client-header", 11): ("confirmed", "evidence/dynamic_checks.log, шаги 1-2: любой X-User-Id принимается"),
}
DEFAULT_BY_PREFIX = {
    "bank.compose-": ("confirmed", "ревью docker-compose.yml (стенд поднят без Docker, проверка по конфигурации)"),
    "bank.redis-without-auth": ("confirmed", "REDIS_URL redis://redis:6379/0 без пароля, образ redis:7 без requirepass"),
    "bank.vulnerable-dependency": ("confirmed", "evidence/pip-audit.json (pip-audit 2026-11-24, OSV/PyPI advisory DB)"),
    "docker-compose.security.": ("true_positive_hardening", "отсутствуют no-new-privileges и read_only — усиление контейнеров"),
}


def triage_for(check_id: str, line: int):
    for (suffix, ln), val in TRIAGE.items():
        if check_id.endswith(suffix) and ln == line:
            return val
    for prefix, val in DEFAULT_BY_PREFIX.items():
        if prefix in check_id:
            return val
    return ("needs_review", "")


def pos(text: str, line: int, last: bool):
    lines = text.splitlines(keepends=True)
    offset = sum(len(l) for l in lines[: line - 1])
    body = lines[line - 1].rstrip("\n")
    if last:
        return {"line": line, "col": len(body) + 1, "offset": offset + len(body)}
    col = len(body) - len(body.lstrip()) + 1
    return {"line": line, "col": col, "offset": offset + col - 1}


def main():
    data = json.loads(RAW.read_text(encoding="utf-8"))
    for r in data["results"]:
        status, ev = triage_for(r["check_id"], r["start"]["line"])
        r["extra"].setdefault("metadata", {})["triage"] = {"status": status, "evidence": ev, "source": "semgrep"}

    for m in json.loads(MANUAL.read_text(encoding="utf-8")):
        src = (ROOT / m["path"]).read_text(encoding="utf-8")
        lines = src.splitlines()
        snippet = "\n".join(lines[m["start_line"] - 1 : m["end_line"]])
        data["results"].append({
            "check_id": m["check_id"],
            "path": m["path"],
            "start": pos(src, m["start_line"], False),
            "end": pos(src, m["end_line"], True),
            "extra": {
                "message": m["message"],
                "metadata": {
                    "cwe": m["cwe"], "owasp": m.get("owasp", []),
                    "impact": m["impact"], "likelihood": m["likelihood"], "confidence": m["confidence"],
                    "category": "security", "fix_recommendation": m["fix"],
                    "triage": {**m["triage"], "source": "manual review"},
                },
                "severity": m["severity"],
                "fingerprint": hashlib.sha256(f'{m["check_id"]}|{m["path"]}|{snippet}'.encode()).hexdigest(),
                "lines": snippet,
                "is_ignored": False,
                "validation_state": "NO_VALIDATOR",
                "engine_kind": "MANUAL",
            },
        })

    sev = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    data["results"].sort(key=lambda r: (sev.get(r["extra"]["severity"], 3), r["path"], r["start"]["line"]))
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    from collections import Counter
    print("total:", len(data["results"]))
    print("by severity:", dict(Counter(r["extra"]["severity"] for r in data["results"])))
    print("by triage:", dict(Counter(r["extra"]["metadata"]["triage"]["status"] for r in data["results"])))
    print("by engine:", dict(Counter(r["extra"].get("engine_kind", "?") for r in data["results"])))


if __name__ == "__main__":
    main()

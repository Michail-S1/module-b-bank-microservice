"""Генерирует модель угроз OWASP Threat Dragon (формат v2.3.0) для банковского микросервиса.
Выход: threat-model/bank-microservice.threatdragon.json — открывается в Threat Dragon
(Desktop: File -> Open; Web: Local Session -> Import), оттуда Report -> Print/Save as PDF.
Запуск из корня репозитория: python3 tools/build_threat_model.py
"""
import json
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "threat-model" / "bank-microservice.threatdragon.json"
NS = uuid.UUID("6f1c2a52-6a3e-4c3b-9d0f-1b2a3c4d5e6f")  # детерминированные id


def uid(name: str) -> str:
    return str(uuid.uuid5(NS, name))


def ports(prefix):
    circle = {"r": 4, "magnet": True, "stroke": "#5F95FF", "strokeWidth": 1, "fill": "#fff",
              "style": {"visibility": "hidden"}}
    groups = {g: {"position": g, "attrs": {"circle": circle}} for g in ("top", "right", "bottom", "left")}
    return {"groups": groups, "items": [{"group": g, "id": uid(f"{prefix}-port-{g}")} for g in groups]}


THREAT_NO = 0


def threat(title, ttype, severity, description, mitigation, status="Open", score=""):
    global THREAT_NO
    THREAT_NO += 1
    # Контрмеры — рекомендации: в сервисе они не внедрены (кроме явно помеченных «Действует:»).
    if not mitigation.startswith(("Рекомендац", "Действует")):
        mitigation = "Рекомендации: " + mitigation[0].lower() + mitigation[1:] if mitigation.startswith("См.") \
            else "Рекомендации: " + mitigation
    return {
        "id": uid(f"threat-{THREAT_NO}"),
        "number": THREAT_NO,
        "title": title,
        "type": ttype,
        "status": status,
        "severity": severity,
        "score": score,
        "description": description,
        "mitigation": mitigation,
        "modelType": "STRIDE",
        "new": False,
    }


def has_open(threats):
    return any(t["status"] == "Open" for t in threats)


def actor(key, name, x, y, desc, threats=(), w=170, h=80):
    threats = list(threats)
    return {
        "position": {"x": x, "y": y}, "size": {"width": w, "height": h},
        "attrs": {"text": {"text": name},
                  "body": {"stroke": "red" if has_open(threats) else "#333333",
                           "strokeWidth": 2.5 if has_open(threats) else 1.5, "strokeDasharray": None}},
        "visible": True, "shape": "actor", "zIndex": 5, "ports": ports(key), "id": uid(key),
        "data": {"type": "tm.Actor", "name": name, "description": desc, "isTrustBoundary": False,
                 "outOfScope": False, "reasonOutOfScope": "", "providesAuthentication": False,
                 "threats": threats, "hasOpenThreats": has_open(threats)},
    }


def process(key, name, x, y, desc, threats, size=170):
    return {
        "position": {"x": x, "y": y}, "size": {"width": size, "height": size},
        "attrs": {"text": {"text": name},
                  "body": {"stroke": "red" if has_open(threats) else "#333333",
                           "strokeWidth": 2.5 if has_open(threats) else 1.5, "strokeDasharray": None}},
        "visible": True, "shape": "process", "zIndex": 5, "ports": ports(key), "id": uid(key),
        "data": {"type": "tm.Process", "name": name, "description": desc, "outOfScope": False,
                 "isTrustBoundary": False, "reasonOutOfScope": "", "handlesCardPayment": False,
                 "handlesGoodsOrServices": False, "isWebApplication": True, "privilegeLevel": "",
                 "threats": threats, "hasOpenThreats": has_open(threats)},
    }


def store(key, name, x, y, desc, threats, creds=False, w=230, h=85):
    line = {"stroke": "red" if has_open(threats) else "#333333",
            "strokeWidth": 2.5 if has_open(threats) else 1.5, "strokeDasharray": None}
    return {
        "position": {"x": x, "y": y}, "size": {"width": w, "height": h},
        "attrs": {"text": {"text": name}, "topLine": dict(line), "bottomLine": dict(line)},
        "visible": True, "shape": "store", "zIndex": 5, "ports": ports(key), "id": uid(key),
        "data": {"type": "tm.Store", "name": name, "description": desc, "outOfScope": False,
                 "isTrustBoundary": False, "reasonOutOfScope": "", "isALog": False, "isEncrypted": False,
                 "isSigned": False, "storesCredentials": creds, "storesInventory": False,
                 "threats": threats, "hasOpenThreats": has_open(threats)},
    }


def flow(key, name, src, dst, desc, threats=(), vertices=(), protocol="", public=False):
    threats = list(threats)
    return {
        "shape": "flow",
        "attrs": {"line": {"stroke": "red" if has_open(threats) else "#333333",
                           "strokeWidth": 2.5 if has_open(threats) else 1.5,
                           "targetMarker": {"name": "block"}, "sourceMarker": {"name": ""},
                           "strokeDasharray": None}},
        "width": 200, "height": 100, "zIndex": 10,
        "labels": [{
            "markup": [{"tagName": "ellipse", "selector": "labelBody"}, {"tagName": "text", "selector": "labelText"}],
            "attrs": {"labelText": {"text": name, "textAnchor": "middle", "textVerticalAnchor": "middle"},
                      "labelBody": {"ref": "labelText", "refRx": "50%", "refRy": "60%", "fill": "#fff", "strokeWidth": 0}},
            "position": {"distance": 0.5, "args": {"keepGradient": True, "ensureLegibility": True}},
        }],
        "connector": "smooth",
        "data": {"type": "tm.Flow", "name": name, "description": desc, "outOfScope": False,
                 "reasonOutOfScope": "", "isBidirectional": False, "isEncrypted": False,
                 "isPublicNetwork": public, "protocol": protocol, "isTrustBoundary": False,
                 "threats": threats, "hasOpenThreats": has_open(threats)},
        "id": uid(key), "source": {"cell": uid(src)}, "target": {"cell": uid(dst)},
        "vertices": [{"x": x, "y": y} for x, y in vertices],
    }


def boundary_box(key, name, x, y, w, h, desc):
    return {
        "position": {"x": x, "y": y}, "size": {"width": w, "height": h},
        "attrs": {"label": {"text": name}}, "visible": True, "shape": "trust-boundary-box",
        "zIndex": -50, "id": uid(key),
        "data": {"type": "tm.BoundaryBox", "name": name, "description": desc, "isTrustBoundary": True,
                 "hasOpenThreats": False},
    }


def text(key, txt, x, y, w, h):
    return {"position": {"x": x, "y": y}, "size": {"width": w, "height": h},
            "attrs": {"text": {"text": txt}}, "visible": True, "shape": "td-text-block", "zIndex": 1,
            "id": uid(key), "data": {"type": "tm.Text", "name": txt, "hasOpenThreats": False}}


LVL = "Уровень применения: "

# ============================ КОРНЕВЫЕ ПРИЧИНЫ ============================
# 22 карточки Threat Dragon — это сценарии STRIDE на элементах DFD; несколько карточек могут выражать
# одну корневую причину (RC). Связи: причина -> сценарий -> последствие.
ROOT_CAUSES = [
    ("RC-1", "Идентичность клиента берётся из заголовка X-User-Id без аутентификации", "подтверждено (код, стенд)",
     [1, 4], "клиентский заголовок → подмена пользователя → IDOR → хищение средств, раскрытие истории"),
    ("RC-2", "Проверка и списание баланса неатомарны, в схеме нет ограничений целостности", "подтверждено (код, стенд)",
     [2, 17], "параллельные переводы → отрицательный остаток → необеспеченные зачисления → риск финансовых потерь"),
    ("RC-3", "Хранилища доступны в обход API: опубликованные порты, пароль по умолчанию, Redis без аутентификации",
     "подтверждено (конфигурация)", [3, 15, 20, 21, 22],
     "сетевой доступ к хосту → вход в СУБД/Redis → изменение балансов и истории, сброс кэша"),
    ("RC-4", "Избыточные привилегии учётной записи БД, учётные данные в конфигурации", "подтверждено (конфигурация)",
     [9, 14], "компрометация API или будущая SQLi → права суперпользователя СУБД"),
    ("RC-5", "Динамическая сборка SQL (f-строки) при действующей bind-параметризации",
     "потенциальный риск: эксплуатация не обнаружена", [5],
     "небезопасная правка кода → SQL Injection → чтение/изменение данных"),
    ("RC-6", "Недостаточный аудит операций в приложении и в СУБД", "подтверждено (код, конфигурация)", [6, 18],
     "атака без следов инициатора → невозможность расследования и доказательства"),
    ("RC-7", "Нет ограничения частоты запросов, тяжёлый поиск ILIKE", "подтверждено (код); DoS не проверялся", [7],
     "массовые запросы → исчерпание пула БД → недоступность"),
    ("RC-8", "Лишняя информация в ответах и интерфейсе API", "подтверждено (код; наблюдения стенда)", [8, 13],
     "отдельный ответ 404 для отсутствующего получателя, открытая схема API → перебор счетов, разведка"),
    ("RC-9", "Уязвимые и незакреплённые зависимости и образы", "подтверждено (pip-audit, конфигурация)", [10],
     "известная CVE в зависимости → DoS/иное воздействие на API"),
    ("RC-10", "Защита каналов не задана в конфигурации: API и Redis — без TLS; для PostgreSQL явно не задано "
              "требование TLS с проверкой имени сервера (фактическое шифрование не проверено)",
     "подтверждено (конфигурация)", [11, 14, 15],
     "перехват или подмена в сети → раскрытие идентификаторов, данных и учётных данных"),
    ("RC-11", "Нет идемпотентности перевода", "подтверждено (код, стенд)", [12],
     "повтор запроса → повторное списание"),
    ("RC-12", "Ошибки логики кэша истории", "подтверждено (стенд)", [16],
     "ключ в Redis → пустая/устаревшая история у клиента"),
    ("RC-13", "Не подтверждены резервное копирование и шифрование данных при хранении",
     "потенциальный риск: нужны данные инфраструктуры", [19],
     "доступ к тому/бэкапу или сбой хранилища → раскрытие или потеря данных"),
]

# Контрмеры TOP-1..3: (тип, мера, что снижает, уровень, проверяемый критерий эффективности)
TOP_MEASURES = {
    1: [
        ("Техническая", "OAuth2/OIDC: JWT от IdP, проверка подписи, iss/aud/exp; user_id = claim sub; "
                        "заголовок X-User-Id отклоняется на шлюзе", "Spoofing — первопричину IDOR (RC-1)",
         "код + инфраструктура (шлюз)", "запрос без токена или с X-User-Id вместо токена → 401"),
        ("Техническая", "Объектная авторизация в том же SQL (WHERE id=$1 AND owner_user_id=$sub), deny-by-default, "
                        "404 для чужих объектов", "EoP/BOLA, перебор ID", "код",
         "токен пользователя A + счёт B → 404, в accounts и transactions 0 изменений"),
        ("Архитектурная", "API-шлюз (TLS, валидация токенов, rate limit); подтверждение перевода вторым фактором; "
                          "непредсказуемые ID счетов (UUID)", "массовую эксплуатацию, кражу сессии, перебор",
         "архитектура / инфраструктура", "перевод без второго фактора не исполняется; перебор ID упирается в лимит"),
        ("Процессная", "Требование «авторизация на каждом эндпоинте»; негативные тесты A→B как блокирующий gate в CI; "
                       "DAST с двумя учётками; security-ревью auth-кода", "повторное появление BOLA", "процесс SDLC",
         "тест A→B выполняется в каждом MR; MR с регрессией не сливается"),
    ],
    2: [
        ("Техническая", "Атомарное условное списание: UPDATE … SET balance=balance-$1 WHERE id=$2 AND owner_user_id=$3 "
                        "AND balance>=$1 RETURNING … (0 строк → отказ) либо SELECT … FOR UPDATE с блокировкой "
                        "счетов по возрастанию id", "TOCTOU, повторное списание сверх остатка (RC-2)", "код",
         "race_check 10×30: 0 раундов с отрицательным остатком, ровно 1 успешный перевод на раунд"),
        ("Техническая", "CHECK (balance_cents >= 0), FOREIGN KEY transactions → accounts; при необходимости SERIALIZABLE "
                        "с повтором", "последствия любой логической ошибки", "инфраструктура (схема БД)",
         "UPDATE, уводящий баланс в минус, отклоняется СУБД (SQLSTATE 23514)"),
        ("Архитектурная", "Обязательный Idempotency-Key + UNIQUE; журнал проводок (ledger) и ежедневная сверка "
                          "остатков с проводками", "дубли операций, незамеченные расхождения", "архитектура",
         "сверка остатков и проводок без расхождений; повтор с тем же ключом не создаёт операцию"),
        ("Процессная", "Конкурентный тест переводов в CI; пункт ревью «финансовая операция атомарна»; алерт на "
                       "отрицательный остаток; лимиты и антифрод", "регрессию, позднее обнаружение",
         "процесс SDLC / эксплуатация", "тест в CI зелёный; алерт срабатывает на тестовом отрицательном остатке"),
    ],
    3: [
        ("Архитектурная", "Убрать ports у postgres и redis; отдельная внутренняя сеть (internal: true / NetworkPolicy), "
                          "доступ только от API; администрирование через bastion/VPN, bind 127.0.0.1",
         "доступность хранилищ злоумышленнику (RC-3)", "инфраструктура",
         "сканирование 5432/6379 с узла вне сети compose → closed/filtered"),
        ("Техническая", "Секреты из Docker secrets/Vault, не в VCS; уникальные пароли и ротация; роль приложения с правами "
                        "только на accounts/transactions; Redis: ACL-пользователь, protected-mode, отключение "
                        "CONFIG/FLUSHALL/MODULE", "вход с паролем по умолчанию, повышение привилегий (RC-3, RC-4)",
         "инфраструктура + конфигурация", "вход postgres/postgres отклонён; роль приложения не может выполнить DDL; "
                                          "AUTH без пароля в Redis отклонён"),
        ("Техническая", "TLS к PostgreSQL (sslmode=verify-full) и Redis (rediss://)",
         "перехват учётных данных и данных (RC-10)", "инфраструктура",
         "подключение без TLS отклоняется сервером (pg_hba hostssl, tls-auth-clients)"),
        ("Процессная", "Semgrep bank.compose-* и секрет-сканинг как блокирующий gate; запрет паролей по умолчанию в "
                       "стандарте конфигурирования; регулярное сканирование периметра", "повторную ошибку конфигурации",
         "процесс SDLC / эксплуатация", "MR с ports: 5432/6379 или паролем-литералом падает на gate"),
    ],
}


# Краткая форма мер для карточки Threat Dragon (в отчёте TD узкие столбцы); полная таблица с уровнями и
# критериями эффективности — threat-model/threat-register.md и REPORT.md (генерируются из TOP_MEASURES).
TOP_CARD_MIT = {
    1: "Т, код + шлюз: OIDC/JWT, user_id = sub, X-User-Id отклоняется.\nТ, код: владение в том же SQL, 404 для "
       "чужих объектов.\nА: API-шлюз, второй фактор для перевода, UUID счетов.\nП: тесты A→B как gate в CI, DAST.\n"
       "Критерий: чужой субъект → 404, 0 изменений в БД.",
    2: "Т, код: условный UPDATE … WHERE balance >= amount RETURNING или SELECT … FOR UPDATE.\nТ, схема БД: "
       "CHECK (balance_cents >= 0), FK.\nА: Idempotency-Key + UNIQUE, журнал проводок и сверка.\nП: конкурентный "
       "тест в CI, алерт на минус.\nКритерий: race_check 10×30 — 0 отрицательных остатков.",
    3: "А, инфраструктура: убрать ports у postgres/redis, внутренняя сеть, bastion.\nТ, конфигурация: секреты из "
       "secret store, роль с минимальными правами, Redis ACL.\nТ: TLS к PostgreSQL и Redis.\nП: gate "
       "bank.compose-*, сканирование периметра.\nКритерий: 5432/6379 извне — closed/filtered.",
}


def measures_text(n):
    return TOP_CARD_MIT[n] + "\nПолная таблица мер — threat-register.md."


# ============================ УГРОЗЫ (карточки Threat Dragon) ============================
# Порядок вызовов задаёт номера карточек 1..22 (совпадают с прежней версией модели).
T_TOP1 = threat(
    "TOP-1. IDOR/BOLA: перевод с чужого счёта и чтение чужой истории через подмену X-User-Id",
    "Elevation of privilege", "Critical",
    "[RC-1] Причина: идентичность берётся из клиентского заголовка X-User-Id без проверки (app/security.py:3-13); "
    "проверка владения (app/crud.py:5-13) сравнивает счёт с этим же значением.\n"
    "Предпосылки: сетевой доступ к API, без учётной записи; ID последовательные.\n"
    "Объекты: для перевода — счёт списания и его владелец; для истории — исходящие операции счетов выбранного "
    "владельца (JOIN по счёту отправителя, не более limit ≤ 100 за запрос; app/crud.py:52-65).\n"
    "Подтверждено: X-User-Id: 1 → перевод со счёта 1 и одна исходящая операция пользователя 1 "
    "(dynamic_checks.log:13-14, 17-18).\n"
    "Импакт: C — High (исходящие операции любого владельца при подстановке его X-User-Id), I — High (списание "
    "с любого счёта), A — нет. "
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N.\n"
    "Бизнес: хищение средств, раскрытие банковской тайны. Связано: #4 (та же причина).",
    measures_text(1), score="9.1 (Critical)")

T_TOP2 = threat(
    "TOP-2. Race condition (TOCTOU) в переводе: списание сверх остатка, отрицательный баланс",
    "Tampering", "Critical",
    "[RC-2] Причина: баланс читается без блокировки (app/crud.py:22), проверка bal < amount — в приложении, затем "
    "отдельный UPDATE (app/crud.py:32); в схеме нет CHECK (balance_cents >= 0).\n"
    "Предпосылки: параллельные запросы со своего счёта — угроза остаётся после исправления TOP-1.\n"
    "Подтверждено: отрицательный остаток отправителя — race_check.log: 4 из 10 раундов (до −30000); дополнительный "
    "прогон race_invariant_check.log: 8 из 10. Получатель зачисляется по каждой успешной операции — необеспеченные "
    "зачисления на сумму отрицательного остатка. Сумма остатков по всем счетам в раунде не менялась: нарушен инвариант "
    "неотрицательного баланса, а не сохранения суммы. Вывод необеспеченных средств не проверялся.\n"
    "Импакт: I — High, C/A — нет. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N (PR:L после TOP-1 → 6.5).\n"
    "Бизнес: риск финансовых потерь, расхождение остатков. Связано: #17.",
    measures_text(2), score="7.5 (High); бизнес: Critical")

T_TOP3 = threat(
    "TOP-3. Доступ к PostgreSQL и Redis в обход API: опубликованные порты, пароль по умолчанию, Redis без пароля",
    "Tampering", "Critical",
    "[RC-3] Причина (microservice/docker-compose.yml): порты 5432 и 6379 опубликованы на всех интерфейсах "
    "(стр. 10-11, 17-18), учётка postgres/postgres (стр. 7-8, 23), Redis без пароля (стр. 24).\n"
    "Предпосылки: сетевой доступ к хосту.\n"
    "Подтверждено: конфигурацией и Semgrep (bank.compose-*); влияние записи в Redis на ответ API — шаг 7. "
    "Подключение к опубликованным портам не выполнялось: стенд работал без Docker.\n"
    "Импакт: C/I/A — High: чтение и изменение балансов и истории, сброс кэша в обход проверок и журналов API. "
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (AV:A = 8.8 для внутреннего сегмента).\n"
    "Бизнес: компрометация ядра переводов, простой. Связано: #15, #20, #21, #22.",
    measures_text(3), score="9.8 (Critical) при доступе из внешней сети")

T_USER_SPOOF = threat(
    "Подмена личности клиента: аутентификации нет, X-User-Id задаёт клиент",
    "Spoofing", "Critical",
    "[RC-1] Сервис принимает любой целочисленный X-User-Id (dynamic_checks.log, шаг 1). "
    "Сценарий эксплуатации — #1 (TOP-1).",
    "См. #1: OIDC/JWT на шлюзе, user_id = sub. Уровень: код + инфраструктура.")

T_SQLI = threat(
    "Потенциальная регрессия к SQL Injection при изменении сборки SQL (search, limit)",
    "Tampering", "Medium",
    "[RC-5] Наблюдение: запрос собирается f-строками (app/crud.py:61, 64); Semgrep: bank.dynamic-sql-fstring, "
    "asyncpg-sqli (app/crud.py:66).\n"
    "Действующая защита (в коде): в f-строку попадают только номера плейсхолдеров $2/$3, значения search и limit "
    "передаются bind-параметрами asyncpg.\n"
    "Задание указывает на SQL Injection; для поставки с SHA-256 b34bebec…6458b3 значения пользователя передаются "
    "параметрами conn.fetch(sql, *params) (app/crud.py:66) — SQL Injection в этом запросе не подтверждена; триаж "
    "Semgrep — false positive по эксплуатируемости. Лог (иллюстрация): ' OR '1'='1 → [] (dynamic_checks.log:25-26).\n"
    "Риск: правка вида f\"... '{search}'\" сделает инъекцию возможной, а работа под суперпользователем (#9) — "
    "максимальной по импакту. Связано: #9.",
    "Действует: bind-параметризация asyncpg.\n"
    "Рекомендации (не внедрены): bank.dynamic-sql-fstring как блокирующий gate; запрет конкатенации SQL в стандарте "
    "кодирования; роль БД без DDL (#9); DAST (sqlmap) на стенде. Уровень: процесс + код + инфраструктура.\n"
    "Критерий: gate падает на тестовом MR с f\"...'{x}'\" в SQL.",
    score="н/п: уязвимость не обнаружена")

T_REPUD = threat(
    "Недостаточный аудит: инициатор перевода не фиксируется",
    "Repudiation", "Medium",
    "[RC-6] В коде нет журналирования; transactions хранит только from/to/amount (app/crud.py:35-38). Access-log uvicorn "
    "(если включён) пишет метод, путь, код ответа и IP, но не инициатора, параметры и решение авторизации. "
    "Атаки #1 и #2 трудно расследовать. Связано: #18.",
    "Append-only аудит (sub, request-id, IP, решение, результат) → SIEM; алерты на всплески 403/404. "
    "Уровень: код + инфраструктура + процесс.")

T_DOS = threat(
    "Отказ в обслуживании: нет rate limiting, поиск ILIKE '%…%' по CAST(id AS TEXT)",
    "Denial of service", "Medium",
    "[RC-7] Нет ограничения частоты; поиск по CAST(t.id AS TEXT) ILIKE не использует индекс, '%' и '_' не "
    "экранируются (шаг 4b: search=_ возвращает всё); пул БД — 5 соединений (app/db.py:9). Нагрузочно не проверялось.",
    "Rate limit и квоты на шлюзе; экранирование wildcard или поиск по точному id; statement_timeout. "
    "Уровень: инфраструктура + код.")

T_INFO_API = threat(
    "Раскрытие информации: /docs и /openapi.json без аутентификации, оракул существования счёта",
    "Information disclosure", "Low",
    "[RC-8] Swagger UI и схема API доступны без аутентификации (шаг 10). Код отвечает 404 'To account not found' "
    "для отсутствующего получателя (app/crud.py:28-30) и продолжает перевод для существующего — это выдаёт "
    "существование счёта (подробно — #13). Связано: #13.",
    "docs_url/openapi_url = None вне dev; единый ответ об ошибке перевода. Уровень: код.")

T_PRIV = threat(
    "Избыточные привилегии: API работает с БД под суперпользователем postgres",
    "Elevation of privilege", "High",
    "[RC-4] DSN postgresql://postgres:postgres@… (docker-compose.yml:23). Компрометация API или будущая SQLi (#5) "
    "дают полные права в СУБД. Связано: #5, #14.",
    "Роль приложения с правами только на accounts/transactions; владелец схемы — отдельная роль. "
    "Уровень: инфраструктура (БД) + стандарт конфигурирования.")

T_SUPPLY = threat(
    "Уязвимые зависимости и образы без дайджеста (supply chain)",
    "Tampering", "Medium",
    "[RC-9] pip-audit: starlette 0.38.6 (транзитивно от fastapi==0.115.0) — 7 уникальных advisory, python-dotenv 1.0.1 — "
    "CVE-2026-28684 (evidence/pip-audit*.json). Образы postgres:16, redis:7 — плавающие теги. Достижимость CVE "
    "разбора multipart для текущих эндпоинтов не подтверждена.",
    "Обновление зависимостей, lock-файл с хэшами, образы по @sha256, SCA-gate в CI, SBOM. "
    "Уровень: процесс + инфраструктура.")

T_F_TLS = threat(
    "Запросы и X-User-Id передаются по HTTP: TLS в предоставленной конфигурации не описан",
    "Information disclosure", "High",
    "[RC-10] docker-compose публикует API на 8000/tcp (стр. 25-26), TLS-терминатора нет. Есть ли TLS на внешнем "
    "ingress, по материалам установить нельзя. Без TLS идентификатор и данные перевода можно перехватить и изменить.",
    "TLS 1.2+/1.3 на ingress/шлюзе, HSTS, отказ от HTTP. Уровень: инфраструктура.")

T_F_REPLAY = threat(
    "Повтор запроса перевода: повторное списание (нет идемпотентности)",
    "Tampering", "Medium",
    "[RC-11] Механизма нет: код не читает Idempotency-Key, уникального ключа операции в transactions нет. "
    "Подтверждено (replay_check.log): два одинаковых POST → 2 операции, списано 5000 вместо 2500; с одинаковым "
    "Idempotency-Key — так же. Связано: #7.",
    "Обязательный Idempotency-Key + UNIQUE(initiator, key); повтор возвращает исходный ответ. Уровень: код + архитектура.\n"
    "Критерий: повтор с тем же ключом → тот же transaction_id, одно списание.")

T_F_ERR = threat(
    "Подробные ошибки в ответах выдают существование счетов",
    "Information disclosure", "Low",
    "[RC-8] Код: после проверки баланса (app/crud.py:22-26) отсутствующий получатель даёт 404 (стр. 28-30), "
    "существующий — перевод выполняется (стр. 32-38). Стенд: счёт списания 2, сумма 1 — получатель 999 → 404 "
    "(dynamic_checks.log:35-36), получатель 1 → HTTP 200 (стр. 50-51, другой шаг). Строки 37-38 (400 Insufficient "
    "funds) иллюстрируют нехватку средств и существование получателя не доказывают. Проба существующего получателя "
    "выполняет реальный перевод. Счёт списания оракулом не является (стр. 23-24 недостижимы после проверки "
    "владения). Связано: #8.",
    "Единый ответ «перевод невозможен», подробности — в журнал. Уровень: код.")

T_F_DB = threat(
    "Канал API → PostgreSQL: требование TLS с проверкой имени сервера не задано; учётка суперпользователя в DSN",
    "Information disclosure", "Medium",
    "[RC-10, RC-4] В конфигурации сервиса явно не задано требование TLS с проверкой имени сервера: create_pool без "
    "ssl= (app/db.py:9), в DSN нет sslmode (docker-compose.yml:23); asyncpg 0.29.0 для TCP тогда использует "
    "sslmode=prefer (без проверки сертификата). Фактическое шифрование соединения не проверено. Отдельно: учётные "
    "данные суперпользователя в DSN (RC-4, #9).",
    "Рекомендации: sslmode=verify-full с проверкой сертификата сервера; секреты из secret store; роль с "
    "минимальными правами. Уровень: инфраструктура + код.")

T_F_REDIS = threat(
    "Канал API → Redis без аутентификации и TLS",
    "Tampering", "Medium",
    "[RC-3, RC-10] REDIS_URL redis://redis:6379/0 без пароля и TLS: участник сети читает и пишет ключи tx:*. "
    "Связано: #3, #16.",
    "ACL-пользователь Redis, rediss://, изоляция сети. Уровень: инфраструктура.")

T_F_CACHE = threat(
    "Cache poisoning: подмена ключа tx:* скрывает историю клиента",
    "Tampering", "Medium",
    "[RC-12; предпосылка — RC-3] При наличии ключа list_transactions возвращает [] без проверки (app/crud.py:46-48); "
    "инвалидация удаляет tx:{uid}, а читаются tx:{uid}:{limit}:{search} (app/crud.py:40, 45). "
    "Подтверждено: SET tx:1:20: x → пустая история (шаги 7, 7b).",
    "Единая функция ключа, версионная инвалидация; не кэшировать финансовые данные без необходимости; "
    "аутентификация Redis. Уровень: код + инфраструктура.")

T_PG_INTEGRITY = threat(
    "Нет ограничений целостности в схеме (CHECK balance >= 0, внешние ключи)",
    "Tampering", "Medium",
    "[RC-2] balance_cents может стать отрицательным, transactions не ссылается на accounts (app/db.py:15-30): "
    "БД не страхует логические ошибки. Связано: #2.",
    "CHECK, FOREIGN KEY, миграции с ревью. Уровень: схема БД + процесс.")

T_PG_AUDIT = threat(
    "Аудит изменений на уровне СУБД не настроен в предоставленной конфигурации",
    "Repudiation", "Medium",
    "[RC-6] В docker-compose нет pgaudit и триггеров аудита; прямые изменения (#3) не фиксируются. Есть ли аудит в "
    "целевой инфраструктуре, по материалам неизвестно. Связано: #6.",
    "pgaudit (write, ddl, role) → SIEM. Уровень: инфраструктура + процесс.")

T_PG_REST = threat(
    "Не подтверждены механизмы резервного копирования и шифрования данных при хранении",
    "Information disclosure", "Medium",
    "[RC-13, потенциальный инфраструктурный риск] В docker-compose том pgdata объявлен без параметров шифрования, "
    "сведений о резервном копировании в материалах нет. Отсутствие этих мер в инфраструктуре банка НЕ установлено.\n"
    "Для подтверждения нужны: конфигурация хранения (тома, диски, LUKS/KMS), политика резервного копирования и "
    "шифрования бэкапов, процедуры и протоколы восстановления (RPO/RTO).",
    "Запросить и проверить перечисленные данные; если мер нет — шифрование томов и бэкапов, регулярное тестовое "
    "восстановление. Уровень: инфраструктура + процесс.")

T_REDIS_DOS = threat(
    "Сброс и подмена кэша без аутентификации (FLUSHALL, CONFIG)",
    "Denial of service", "High",
    "[RC-3] Redis без пароля на опубликованном 6379: сброс данных, изменение конфигурации, исчерпание памяти. "
    "Это сценарий TOP-3 (#3) для Redis.",
    "См. #3: убрать публикацию порта, ACL, отключить опасные команды, maxmemory. Уровень: инфраструктура.")

T_NET_PG = threat(
    "Подключение к PostgreSQL с учётной записью по умолчанию postgres/postgres",
    "Tampering", "Critical",
    "[RC-3] Поток существует из-за ports: 5432:5432 и пароля по умолчанию. Сценарий TOP-3 (#3).",
    "См. #3. Уровень: инфраструктура.")

T_NET_REDIS = threat(
    "Подключение к Redis без аутентификации",
    "Tampering", "High",
    "[RC-3] Поток существует из-за ports: 6379:6379. Сценарий TOP-3 (#3).",
    "См. #3. Уровень: инфраструктура.")

# ============================ DFD ============================
cells = [
    text("title", "Bank Microservice — DFD (уровень 1), STRIDE.\nКрасным — элементы с открытыми угрозами.\n"
                  "TOP-1/2/3 — наиболее критичные угрозы.\n22 карточки = 13 корневых причин (RC-1…13)", 20, 5, 360, 80),
    boundary_box("tb-host", "Граница доверия: Docker-хост / сеть compose", 240, 90, 980, 610,
                 "Хост с docker-compose. Порты 8000, 5432, 6379 опубликованы на всех интерфейсах хоста, "
                 "поэтому граница фактически проницаема для слоя данных."),
    boundary_box("tb-data", "Граница доверия: слой данных", 800, 130, 400, 530,
                 "PostgreSQL и Redis. Должны быть доступны только API; сейчас доступны напрямую из сети."),
    actor("user", "Клиент банка\n(веб/мобильное\nприложение)", 20, 300,
          "Внешняя сущность. Вызывает API по HTTP, передаёт X-User-Id.", [T_USER_SPOOF]),
    actor("net", "Узел сети хоста /\nадминистратор", 1280, 330,
          "Любой узел, имеющий сетевой доступ к хосту: администратор, другой сервис, злоумышленник в сегменте. "
          "Легитимного сценария прямого доступа нет — поток возникает из-за конфигурации.", w=180),
    process("api", "Bank Microservice API\n(FastAPI + uvicorn\n:8000)", 520, 280,
            "Backend REST API: POST /transfer, GET /transactions. Python 3, FastAPI 0.115.0, asyncpg, redis-py. "
            "Идентификация по заголовку X-User-Id.",
            [T_TOP1, T_TOP2, T_SQLI, T_PRIV, T_REPUD, T_DOS, T_SUPPLY, T_INFO_API]),
    store("pg", "PostgreSQL 16\n(БД bank: accounts, transactions)", 900, 180,
          "Счета (owner_user_id, balance_cents) и журнал переводов. Порт 5432 опубликован, "
          "учётка postgres/postgres.", [T_TOP3, T_PG_INTEGRITY, T_PG_AUDIT, T_PG_REST], creds=True, w=250),
    store("redis", "Redis 7\n(кэш истории tx:{uid}:{limit}:{search})", 900, 500,
          "Кэш выдачи истории транзакций. Без аутентификации, порт 6379 опубликован.", [T_REDIS_DOS], w=250),
    flow("f-transfer", "1. POST /transfer\n{from, to, amount}\n+ X-User-Id", "user", "api",
         "Запрос перевода. HTTP; TLS в предоставленной конфигурации не описан.", [T_F_TLS, T_F_REPLAY], [(370, 285)], "HTTP", True),
    flow("f-history", "2. GET /transactions\n?limit&search\n+ X-User-Id", "user", "api",
         "Запрос истории транзакций. HTTP; TLS в предоставленной конфигурации не описан.", [], [(370, 375)], "HTTP", True),
    flow("f-resp", "3. Ответ: tx_id /\nистория / ошибки", "api", "user",
         "JSON-ответы API: transaction_id, история транзакций, ошибки 400/403/404.", [T_F_ERR], [(370, 470)], "HTTP", True),
    flow("f-sql", "4. SQL-запросы\n(перевод, история)", "api", "pg",
         "Проверка владения, чтение баланса, UPDATE балансов, INSERT в transactions, SELECT истории. "
         "asyncpg, пул 5 соединений; требование TLS явно не задано (asyncpg: sslmode=prefer), суперпользователь postgres.", [T_F_DB], [(760, 215)], "PostgreSQL wire"),
    flow("f-sql-r", "5. Результаты\nзапросов", "pg", "api",
         "Баланс, признак владения, строки transactions.", [], [(790, 310)], "PostgreSQL wire"),
    flow("f-cache", "6. GET/DEL tx:*", "api", "redis",
         "GET tx:{uid}:{limit}:{search}; после перевода DEL tx:{uid}.", [T_F_REDIS], [(760, 470)], "RESP"),
    flow("f-cache-r", "7. Значение\nкэша", "redis", "api",
         "При попадании в кэш API возвращает пустой список.", [T_F_CACHE], [(780, 580)], "RESP"),
    flow("f-net-pg", "8. Прямое подключение\n:5432 postgres/postgres", "net", "pg",
         "Возможен из-за ports: 5432:5432.", [T_NET_PG], [(1250, 250)], "PostgreSQL wire", True),
    flow("f-net-redis", "9. Прямое подключение\n:6379 без auth", "net", "redis",
         "Возможен из-за ports: 6379:6379.", [T_NET_REDIS], [(1250, 500)], "RESP", True),
]

model = {
    "version": "2.3.0",
    "summary": {
        "title": "Bank Microservice — модель угроз (перевод средств и история транзакций)",
        "owner": "Curmyc",
        "description": (
            "Объект: микросервис банка (microservice.zip, файлы от 2026-09-23): REST API на FastAPI "
            "(POST /transfer, GET /transactions), PostgreSQL 16, Redis 7 (кэш истории), docker-compose.\n"
            "Методология: DFD уровня 1 + STRIDE per element; критичность = CVSS 3.1 + влияние на бизнес. "
            "Источники: ручной анализ кода, Semgrep, динамические проверки на локальном стенде (evidence/).\n"
            "Счёт угроз: 22 карточки — сценарии STRIDE на элементах DFD; они сводятся к 13 корневым причинам "
            "(RC-1…RC-13): 11 подтверждены, 2 — потенциальные риски (RC-5 — регрессия к SQLi, RC-13 — хранение и "
            "бэкапы). Метка [RC-n] и «Связано: #…» в карточке указывают причину и связанные карточки; полная "
            "таблица — threat-model/threat-register.md.\n"
            "Ограничения: в материалах не описаны IdP, API-шлюз и ingress; выводы о конфигурации относятся к "
            "предоставленным файлам, а не ко всей инфраструктуре банка. В поставке сервис не стартует (main.py "
            "импортирует несуществующие имена user_id, TransferIn, TxOut; Dockerfile отсутствует) — проверки "
            "выполнены через харнесс с алиасами, код не менялся."),
        "id": 0,
    },
    "detail": {
        "contributors": [{"name": "Curmyc"}],
        "diagrams": [{
            "id": 0, "version": "2.3.0", "title": "DFD: Bank Microservice (уровень 1)", "diagramType": "STRIDE",
            "description": "Потоки 1-7 — штатная работа сервиса; потоки 8-9 — прямой доступ к хранилищам, "
                           "который возможен из-за опубликованных портов.",
            "placeholder": "", "thumbnail": "./public/content/images/thumbnail.stride.jpg", "cells": cells,
        }],
        "diagramTop": 1,
        "reviewer": "",
        "threatTop": THREAT_NO,
    },
}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(model, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"written {OUT.relative_to(ROOT)}: {len(cells)} cells, {THREAT_NO} threats")

# ============================ Читабельный реестр и блоки REPORT.md ============================
import re
from collections import Counter

ELEMENT_LABEL = {}
for c in cells:
    d = c["data"]
    if d.get("type") in ("tm.Text", "tm.BoundaryBox"):
        continue
    label = d["name"].replace("\n", " ")
    if d["type"] == "tm.Flow":
        label = "Поток " + d["name"].split("\n")[0]
    for t in d.get("threats", []):
        ELEMENT_LABEL[t["number"]] = (label, t)
CARDS = [ELEMENT_LABEL[n] for n in sorted(ELEMENT_LABEL)]
RC_OF = {}
for rc, *_rest in ROOT_CAUSES:
    for n in _rest[2]:
        RC_OF.setdefault(n, []).append(rc)
assert sorted(RC_OF) == list(range(1, THREAT_NO + 1)), "каждая карточка должна относиться к корневой причине"

def esc(s):
    return s.replace("|", "\\|").replace("\n", " ")

sev = Counter(t["severity"] for _, t in CARDS)
st = Counter(t["status"] for _, t in CARDS)
open_sev = Counter(t["severity"] for _, t in CARDS if t["status"] == "Open")
confirmed = sum(1 for r in ROOT_CAUSES if r[2].startswith("подтверждено"))
SUMMARY = (f"Карточек угроз в Threat Dragon: **{THREAT_NO}** (сценарии STRIDE на элементах DFD); "
           f"статус: Open — {st.get('Open', 0)}, Mitigated — {st.get('Mitigated', 0)}. "
           f"Открытые по критичности: Critical — {open_sev.get('Critical', 0)}, High — {open_sev.get('High', 0)}, "
           f"Medium — {open_sev.get('Medium', 0)}, Low — {open_sev.get('Low', 0)}.\n\n"
           f"Независимых корневых причин: **{len(ROOT_CAUSES)}** — {confirmed} подтверждены материалами "
           f"(код, конфигурация, стенд), {len(ROOT_CAUSES) - confirmed} — потенциальные риски без подтверждённой "
           f"эксплуатации (RC-5, RC-13).")

RC_TABLE = "| RC | Корневая причина | Статус | Карточки TD | Причина → сценарий → последствие |\n|---|---|---|---|---|\n" + \
    "\n".join(f"| {rc} | {esc(name)} | {status} | {', '.join('#%d' % n for n in nums)} | {esc(chain)} |"
              for rc, name, status, nums, chain in ROOT_CAUSES)

CARD_TABLE = "| № TD | Элемент DFD | Угроза | STRIDE | Критичность | Статус | RC |\n|---|---|---|---|---|---|---|\n" + \
    "\n".join(f"| {t['number']} | {esc(el)} | {esc(t['title'])} | {t['type']} | {t['severity']} | {t['status']} | "
              f"{', '.join(RC_OF[t['number']])} |" for el, t in CARDS)

def measures_table(n):
    return ("| Тип | Рекомендуемая контрмера (не внедрена) | Что снижает | Уровень | Проверяемый критерий эффективности |\n|---|---|---|---|---|\n" +
            "\n".join(f"| {t} | {esc(m)} | {esc(r)} | {lvl} | {esc(c)} |" for t, m, r, lvl, c in TOP_MEASURES[n]))

TOP_MD = "\n\n".join(f"#### {ELEMENT_LABEL[n][1]['title']}\n\n{measures_table(n)}" for n in (1, 2, 3))

reg = [f"# Реестр угроз — Bank Microservice (читабельная версия)\n",
       "> Сгенерирован `tools/build_threat_model.py` из того же источника, что и модель "
       "`bank-microservice.threatdragon.json`. **Это не экспорт OWASP Threat Dragon**: экспорт — "
       "`threat-model-report.pdf`. Документ нужен, потому что в отчёте Threat Dragon таблицы карточек узкие.\n",
       "## Сводка\n", SUMMARY + "\n",
       "## Корневые причины и связи карточек\n", RC_TABLE + "\n",
       "## Карточки Threat Dragon\n", CARD_TABLE + "\n",
       "## TOP-1…TOP-3: контрмеры и критерии эффективности\n", TOP_MD + "\n",
       "## Описания и меры по всем карточкам\n"]
for el, t in CARDS:
    reg.append(f"### #{t['number']}. {t['title']}\n\n*Элемент:* {el} · *STRIDE:* {t['type']} · "
               f"*Критичность:* {t['severity']} · *Статус:* {t['status']}" +
               (f" · *Оценка:* {t['score']}" if t['score'] else "") +
               f"\n\n**Описание.** {t['description']}\n\n**Меры.** {t['mitigation']}\n")
(ROOT / "threat-model" / "threat-register.md").write_text("\n".join(reg).replace("\n", "\n").rstrip() + "\n",
                                                        encoding="utf-8")

def put_block(path, name, content):
    text_ = path.read_text(encoding="utf-8")
    pat = re.compile(rf"(<!-- GEN:{name} -->\n)(?:.*?\n)?(<!-- /GEN:{name} -->)", re.S)
    if not pat.search(text_):
        raise SystemExit(f"нет маркера GEN:{name} в {path.name}")
    path.write_text(pat.sub(lambda m: m.group(1) + content.rstrip("\n") + "\n" + m.group(2), text_), encoding="utf-8")

report = ROOT / "REPORT.md"
if "<!-- GEN:" in report.read_text(encoding="utf-8"):
    put_block(report, "summary", SUMMARY)
    put_block(report, "rc-table", RC_TABLE)
    put_block(report, "card-table", CARD_TABLE)
    put_block(report, "top-measures", TOP_MD)
    print("REPORT.md: блоки GEN обновлены")
print("written threat-model/threat-register.md")

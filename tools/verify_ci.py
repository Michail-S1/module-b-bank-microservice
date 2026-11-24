"""Проверка примера GitLab CI без GitLab. Запуск из корня комплекта:
    python3 tools/verify_ci.py            # статические проверки
    python3 tools/verify_ci.py --run      # + локальное выполнение script/before_script заданий
Статика: разбор YAML; валидация по JSON-схеме GitLab CI (evidence/verification/schemas/gitlab-ci.schema.json,
взята из зеркала github.com/gitlabhq/gitlabhq, master); каждый элемент script — строка; нет `when` вместе с `rules`;
файлы и каталоги, на которые ссылаются команды, существуют; artifacts:when=always у сканеров.
--run: каждое задание (кроме upload-defectdojo) выполняется в bash во временной копии репозитория (git init + commit),
с переменными из `variables`; инструменты должны быть в PATH (semgrep 1.186.0, pip-audit, gitleaks, trivy).
Это проверка команд и кодов выхода, а НЕ эмуляция GitLab runner/образов Docker.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent
CI = ROOT / "ci" / "security-pipeline.gitlab-ci.yml"
SCHEMA = ROOT / "evidence" / "verification" / "schemas" / "gitlab-ci.schema.json"
SARIF_SCHEMA = ROOT / "evidence" / "verification" / "schemas" / "sarif-schema-2.1.0.json"
RESERVED = {"stages", "variables", "default", "include", "workflow", "image", "services", "cache",
            "before_script", "after_script"}
fails = []


def check(cond, msg):
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


doc = yaml.safe_load(CI.read_text(encoding="utf-8"))
check(isinstance(doc, dict), "YAML разобран")
schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
errs = sorted(jsonschema.Draft7Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
for e in errs[:10]:
    print("     schema:", "/".join(map(str, e.path)), "-", e.message[:160])
check(not errs, f"валидация по схеме GitLab CI: {len(errs)} ошибок")

jobs = {k: v for k, v in doc.items() if k not in RESERVED and not k.startswith(".")}
check(set(doc["stages"]) >= {j.get("stage") for j in jobs.values()}, "все stage заданий объявлены в stages")
for name, job in jobs.items():
    for key in ("before_script", "script"):
        for i, line in enumerate(job.get(key, [])):
            check(isinstance(line, str), f"{name}.{key}[{i}] — строка ({type(line).__name__})")
    check(not ("rules" in job and "when" in job), f"{name}: нет job-level when вместе с rules")
    if name not in ("upload-defectdojo", "sast-semgrep-gate"):  # gate и загрузка артефактов не создают
        check(job.get("artifacts", {}).get("when") == "always", f"{name}: artifacts:when=always")
    for need in job.get("needs", []):
        n = need["job"] if isinstance(need, dict) else need
        check(n in jobs, f"{name}: needs -> {n} существует")

text = CI.read_text(encoding="utf-8")
for ref in ("tools/run_semgrep.sh", "tools/semgrep_gate.py", "microservice/requirements.txt", "microservice"):
    check(ref in text and (ROOT / ref).exists(), f"путь {ref} используется и существует")
check(not re.search(r"-r\s+requirements\.txt", text), "нет pip-audit -r requirements.txt (неверный путь)")
check("reports:\n      # SARIF" in text or "sarif: semgrep.sarif" in text, "SARIF публикуется через artifacts:reports:sarif")
check(not re.search(r"sast:\s*semgrep\.sarif", text), "SARIF не объявлен как reports:sast")
sha_ci = doc["variables"]["SEMGREP_RULES_SHA"]
sha_sh = re.search(r'RULES_SHA="([0-9a-f]{40})"', (ROOT / "tools/run_semgrep.sh").read_text()).group(1)
check(sha_ci == sha_sh, f"SHA правил совпадает в CI и run_semgrep.sh ({sha_ci[:12]})")

if "--run" in sys.argv:
    expected = {"sast-semgrep-report": 0, "sast-semgrep-gate": 1, "sca-pip-audit": 1,
                "secrets-gitleaks": 0, "iac-trivy": 0}
    artifacts = {"sast-semgrep-report": ["semgrep.json", "semgrep.sarif"], "sca-pip-audit": ["pip-audit.json"],
                 "secrets-gitleaks": ["gitleaks.json"], "iac-trivy": ["trivy-config.json"]}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(".community-rules", "__pycache__", "*.zip"))
        if (ROOT / ".community-rules").is_dir():  # кэш правил, чтобы не скачивать повторно (SHA проверяется скриптом)
            shutil.copytree(ROOT / ".community-rules", work / ".community-rules")
        subprocess.run("git init -q && git add -A && git -c user.email=ci@local -c user.name=ci commit -qm ci",
                       shell=True, cwd=work, check=True)
        env = dict(os.environ, **{k: str(v) for k, v in doc["variables"].items()}, CI_PROJECT_DIR=str(work))
        for name, code in expected.items():
            job = jobs[name]
            cmds = job.get("before_script", []) + job["script"]
            p = subprocess.run(["bash", "-ec", "\n".join(cmds)], cwd=work, env=env, capture_output=True, text=True)
            tail = (p.stdout + p.stderr).strip().splitlines()[-3:]
            for l in tail:
                print("     |", l[:150])
            check(p.returncode == code, f"run {name}: exit={p.returncode} (ожидалось {code})")
            for a in artifacts.get(name, []):
                f = work / a
                ok = f.is_file() and f.stat().st_size > 0
                if ok and a.endswith((".json", ".sarif")):
                    data = json.loads(f.read_text(encoding="utf-8"))
                    if a == "semgrep.sarif":
                        sarif_errs = list(jsonschema.Draft7Validator(
                            json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))).iter_errors(data))
                        n = sum(len(r.get("results", [])) for r in data["runs"])
                        check(data.get("version") == "2.1.0" and not sarif_errs,
                              f"semgrep.sarif: SARIF {data.get('version')}, ошибок схемы {len(sarif_errs)}, results={n}")
                    if a == "semgrep.json":
                        check(len(data["results"]) == 25, f"semgrep.json: {len(data['results'])} находок (ожидалось 25)")
                check(ok, f"артефакт {a} создан")

print("\nИТОГ:", "все проверки пройдены" if not fails else f"{len(fails)} проверок не прошли")
sys.exit(1 if fails else 0)

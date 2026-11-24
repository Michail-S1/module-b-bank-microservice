#!/usr/bin/env bash
# Сквозная проверка комплекта. Запуск из корня: bash tools/verify_all.sh [--run-ci]
# Логи пишутся в evidence/verification/. Для --run-ci нужны semgrep 1.186.0, pip-audit, gitleaks, trivy в PATH.
set -u
V=evidence/verification; rc=0
run() { local name=$1; shift; "$@" > "$V/$name" 2>&1; local c=$?; echo "$(printf '%-24s' "$name") exit=$c  $(tail -1 "$V/$name")"; [ $c -eq 0 ] || rc=1; }
run docs-check.log     python3 tools/verify_docs.py
# ci-check.log хранит прогон с выполнением команд (--run-ci); статическая проверка пишется отдельно
if [ -n "${1:-}" ]; then run ci-check.log python3 tools/verify_ci.py --run
else run ci-static-check.log python3 tools/verify_ci.py; fi
run semgrep-check.log  python3 tools/verify_semgrep.py semgrep/rerun/semgrep-raw-rerun.json
run pdf-check.log      python3 tools/verify_pdf.py
if [ -f "$V/microservice-sha256.txt" ]; then
  grep -E '^[0-9a-f]{64}  \./' "$V/microservice-sha256.txt" | head -9 > /tmp/_orig.sha
  (cd microservice && find . -type f | sort | xargs sha256sum) | diff -q /tmp/_orig.sha - >/dev/null \
    && echo "microservice-sha256       exit=0  совпадает с исходным архивом" || { echo "microservice-sha256 DIFFERENT"; rc=1; }
fi
exit $rc

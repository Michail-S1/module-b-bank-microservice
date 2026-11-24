#!/usr/bin/env bash
# Воспроизводимый прогон Semgrep для модуля B. Запуск из корня комплекта:
#   bash tools/run_semgrep.sh [out.json] [out.sarif]
# По умолчанию пишет в semgrep/rerun/semgrep-raw-rerun.json и НЕ трогает исходный semgrep/semgrep-raw.json.
# Зафиксировано:
#   Semgrep OSS            1.186.0  (pip install "semgrep==1.186.0" "setuptools<81")
#   semgrep/semgrep-rules  a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2 (коммит от 2026-11-10)
# Сеть нужна только для получения правил с GitHub; реестр semgrep.dev не используется.
set -euo pipefail

SEMGREP_VERSION="1.186.0"
RULES_REPO="https://github.com/semgrep/semgrep-rules.git"
RULES_SHA="a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2"
RULES_DIR=".community-rules"
OUT="${1:-semgrep/rerun/semgrep-raw-rerun.json}"
SARIF="${2:-}"

actual="$(semgrep --version)"
if [[ "$actual" != "$SEMGREP_VERSION" ]]; then
  echo "ERROR: нужен semgrep $SEMGREP_VERSION, установлен $actual" >&2
  exit 2
fi

if [[ ! -d "$RULES_DIR/.git" ]]; then
  git init -q "$RULES_DIR"
  git -C "$RULES_DIR" remote add origin "$RULES_REPO"
fi
if [[ "$(git -C "$RULES_DIR" rev-parse -q --verify HEAD 2>/dev/null || true)" != "$RULES_SHA" ]]; then
  git -C "$RULES_DIR" fetch -q --depth 1 origin "$RULES_SHA"
  git -C "$RULES_DIR" checkout -q --detach FETCH_HEAD
fi
test "$(git -C "$RULES_DIR" rev-parse HEAD)" = "$RULES_SHA"
echo "rules: $RULES_SHA, semgrep: $actual"

mkdir -p "$(dirname "$OUT")"
extra=()
[[ -n "$SARIF" ]] && extra+=(--sarif-output="$SARIF")
# Без --error: код выхода 0 при наличии находок; блокировку делает отдельный шаг (tools/semgrep_gate.py)
semgrep scan --metrics=off --disable-version-check \
  --config "$RULES_DIR/python" --config "$RULES_DIR/yaml" \
  --config "$RULES_DIR/generic/secrets" --config "$RULES_DIR/dockerfile" \
  --config semgrep/custom-rules.yml \
  "${extra[@]}" microservice --json -o "$OUT"
echo "written: $OUT${SARIF:+, $SARIF}"

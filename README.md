# Модуль B — модель угроз и SAST банковского микросервиса

Основной отчёт: **[REPORT.md](REPORT.md)**. Исправления по замечаниям аудитов (ИСПР-01…14): **[AUDIT_FIXES.md](AUDIT_FIXES.md)**.

Редакция 3 (2026-11-25). Оригинал организатора — `microservice.zip`, SHA-256 `b34bebec03ce185cbfc7bfbf5f21cf2dffcc7a1e77ca8eb5c548421ec46458b3`; файлы `microservice/` совпадают с ним побайтно. Контрмеры — рекомендации, в сервисе не внедрены.

**Сдача:** участник отправляет боту `@lilskills_bot` ФИО и HTTPS-ссылку на опубликованную копию комплекта (страница с отчётом и всеми файлами по тем же путям; собирается `tools/build_publication.py`). Опубликованная копия: https://claude.ai/artifact/V65DffWqmJcnMckG5TUVhD — доступ проверяющему открывает участник.

```
REPORT.md                                  отчёт: DFD, топ-3 угрозы и контрмеры, SAST, SDLC-процесс
AUDIT_FIXES.md                             таблица исправлений ИСПР-01…ИСПР-10 и их проверка
threat-model/
  bank-microservice.threatdragon.json      модель OWASP Threat Dragon v2 (DFD + 22 карточки STRIDE, 13 корневых причин)
  threat-model-report.pdf                  PDF, напечатанный из Threat Dragon 2.6.2 (A4 альбомная, масштаб 90 %)
  dfd.png / dfd.svg                        экспорт DFD из Threat Dragon
  threat-register.md / .pdf                читабельный реестр (НЕ экспорт Threat Dragon): корневые причины, карточки,
                                           контрмеры TOP-1…3 с критериями эффективности
  report-preview.png                       снимок экрана отчёта в Threat Dragon
semgrep/
  custom-rules.yml                         16 кастомных правил
  semgrep-raw.json                         исходный вывод `semgrep --json` (25 находок, не изменялся)
  manual-findings.json                     ручные находки (IDOR и др.)
  semgrep-results.json                     ИТОГ: 25 автоматических + 6 MANUAL (в т.ч. 2 IDOR) + триаж
  rerun/semgrep-raw-rerun.json             повторный прогон с закреплёнными версиями (совпал с исходным)
ci/security-pipeline.gitlab-ci.yml         ПРИМЕР security-стадии GitLab CI (в GitLab не запускался)
evidence/                                  логи стенда, SCA, проверки комплекта (описание — evidence/README.md)
tools/                                     генерация модели и PDF, Semgrep, слияние JSON, проверки, сборка публикации
microservice/                              исследуемый код без изменений (SHA-256 = исходный архив)
```

## Воспроизведение

Все команды выполняются из корня комплекта.

**Semgrep** (версия 1.186.0 и SHA правил `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2` проверяются скриптом):
```bash
python3 -m pip install "semgrep==1.186.0" "setuptools<81"
bash tools/run_semgrep.sh && python3 tools/merge_findings.py
python3 tools/verify_semgrep.py semgrep/rerun/semgrep-raw-rerun.json
```

**Модель угроз:**
```bash
python3 tools/build_threat_model.py   # JSON + threat-register.md + блоки GEN в REPORT.md
```
Затем откройте JSON в Threat Dragon (Import / Open) → Report → Печать. Автоматически: `tools/td_render_report.py` (нужны Threat Dragon web и Playwright).

**Проверки комплекта:**
```bash
python3 tools/verify_ci.py [--run]
python3 tools/verify_pdf.py
```
Динамические проверки на стенде — `evidence/README.md`.

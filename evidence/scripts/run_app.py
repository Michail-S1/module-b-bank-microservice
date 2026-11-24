"""Тестовый харнесс: запускает сервис БЕЗ изменения его кода.
В исходниках main.py импортирует имена, которых нет (user_id, TransferIn, TxOut) —
сервис в поставке не стартует. Для динамической проверки подставляем алиасы
на существующие объекты перед импортом app.main."""
import sys

sys.path.insert(0, sys.argv[1])  # путь к распакованному репозиторию

import app.security as sec
import app.schemas as sch

sec.user_id = sec.get_current_user_id
sch.TransferIn = sch.TransferRequest
sch.TxOut = sch.TransactionOut

import uvicorn
from app.main import app

uvicorn.run(app, host="127.0.0.1", port=int(sys.argv[2]), log_level="warning")

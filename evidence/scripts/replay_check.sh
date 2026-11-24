#!/usr/bin/env bash
# ИСПР-04. Повторная отправка одинакового запроса перевода на ЛОКАЛЬНОМ стенде (127.0.0.1).
# Отдельно проверяются:
#   A) отсутствие механизма идемпотентности — заголовок Idempotency-Key сервис игнорирует;
#   B) фактическое повторное списание — два одинаковых POST дают две операции и двойное списание.
# Тестовые счета 10 (владелец 10, 100000) и 11 (владелец 11, 0) создаются заново перед прогоном.
# Запуск: bash replay_check.sh > ../replay_check.log
API=${API:-http://127.0.0.1:18000}
PSQL="psql -h 127.0.0.1 -p 55432 -U postgres bank -At -F | "
BODY='{"from_account_id":10,"to_account_id":11,"amount_cents":2500}'

state() {
  echo "  accounts (id | owner | balance_cents):"
  $PSQL -c "select id, owner_user_id, balance_cents from accounts where id in (10,11) order by id" | sed 's/^/    /'
  echo "  transactions from 10 -> 11: $($PSQL -c "select count(*) from transactions where from_account_id=10 and to_account_id=11")"
}
post() {  # $1 — метка, далее — дополнительные заголовки curl
  local label=$1; shift
  echo "\$ curl -X POST $API/transfer -H 'X-User-Id: 10' $* -d '$BODY'   # $label"
  curl -s -w '  -> HTTP %{http_code}\n' -X POST "$API/transfer" \
       -H 'X-User-Id: 10' -H 'Content-Type: application/json' "$@" -d "$BODY"
}

echo "# replay_check.sh — $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC), API=$API"
echo "### 0. Подготовка тестовых счетов"
$PSQL -c "delete from transactions where from_account_id in (10,11) or to_account_id in (10,11)" >/dev/null
$PSQL -c "insert into accounts(id, owner_user_id, balance_cents) values (10,10,100000),(11,11,0)
          on conflict (id) do update set owner_user_id=excluded.owner_user_id, balance_cents=excluded.balance_cents" >/dev/null
state

echo; echo "### B. Два одинаковых POST /transfer без Idempotency-Key"
post "запрос 1"
post "запрос 2 (байт-в-байт тот же)"
state
echo "  ожидание при наличии идемпотентности: 1 операция, баланс 10 = 97500"

echo; echo "### A. Два одинаковых POST с одинаковым Idempotency-Key: заголовок игнорируется?"
post "запрос 3" -H 'Idempotency-Key: 3f6c1d2e-replay-test'
post "запрос 4 (тот же ключ)" -H 'Idempotency-Key: 3f6c1d2e-replay-test'
state

echo; echo "### Строки transactions 10 -> 11"
$PSQL -c "select id, from_account_id, to_account_id, amount_cents, created_at from transactions
          where from_account_id=10 and to_account_id=11 order by id" | sed 's/^/  /'

echo; echo "### Итог (вычислено из БД)"
n=$($PSQL -c "select count(*) from transactions where from_account_id=10 and to_account_id=11")
b10=$($PSQL -c "select balance_cents from accounts where id=10")
b11=$($PSQL -c "select balance_cents from accounts where id=11")
echo "  POST отправлено: 4 (2 пары одинаковых), операций создано: $n"
echo "  баланс 10: 100000 -> $b10 (списано $((100000 - b10))), баланс 11: 0 -> $b11"
echo "  сумма по счетам 10+11 до: 100000, после: $((b10 + b11))"

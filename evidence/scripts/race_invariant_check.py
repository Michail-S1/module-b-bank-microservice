"""ИСПР-08. Дополнение к race_check.py (тот не трогается): тот же сценарий гонки, но в каждом раунде
фиксируются баланс отправителя (счёт 3), баланс получателя (счёт 2) и сумма остатков по всем счетам.
Цель — отделить подтверждённое (отрицательный остаток, необеспеченное зачисление получателю)
от неподтверждённого (рост суммарных средств в системе).
Запуск (локальный стенд): python race_invariant_check.py http://127.0.0.1:18000 10 30 > ../race_invariant_check.log
"""
import asyncio
import subprocess
import sys
from datetime import datetime, timezone

import httpx

API, ROUNDS, N = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
PSQL = ["psql", "-h", "127.0.0.1", "-p", "55432", "-U", "postgres", "bank", "-At", "-c"]
AMOUNT = 10000


def sql(q):
    return subprocess.run(PSQL + [q], capture_output=True, text=True, check=True).stdout.strip()


def snapshot():
    b3 = int(sql("select balance_cents from accounts where id=3"))
    b2 = int(sql("select balance_cents from accounts where id=2"))
    total = int(sql("select sum(balance_cents) from accounts"))
    tx = int(sql("select count(*) from transactions where from_account_id=3"))
    return b3, b2, total, tx


async def main():
    print(f"# race_invariant_check.py — {datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ} (UTC), "
          f"{ROUNDS} раундов x {N} параллельных POST /transfer 3 -> 2 на {AMOUNT}, стартовый баланс счёта 3 = {AMOUNT}")
    print("round | HTTP200 | new tx | bal3 после | bal2 прирост | необеспечено (= -bal3) | сумма всех счетов до -> после")
    body = {"from_account_id": 3, "to_account_id": 2, "amount_cents": AMOUNT}
    reproduced = 0
    async with httpx.AsyncClient(base_url=API, limits=httpx.Limits(max_connections=N), timeout=30) as c:
        for rnd in range(1, ROUNDS + 1):
            sql(f"update accounts set balance_cents={AMOUNT} where id=3")
            b3_0, b2_0, tot_0, tx_0 = snapshot()
            rs = await asyncio.gather(*[c.post("/transfer", json=body, headers={"X-User-Id": "3"}) for _ in range(N)])
            b3, b2, tot, tx = snapshot()
            ok = sum(r.status_code == 200 for r in rs)
            unsecured = max(0, -b3)
            reproduced += b3 < 0
            print(f"{rnd:5} | {ok:7} | {tx - tx_0:6} | {b3:10} | {b2 - b2_0:12} | {unsecured:22} | {tot_0} -> {tot}")
    print(f"\nраундов с отрицательным остатком: {reproduced} из {ROUNDS}")
    print("инвариант 'сумма остатков постоянна' проверяется последним столбцом (до/после каждого раунда)")


asyncio.run(main())

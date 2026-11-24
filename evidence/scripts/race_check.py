"""Проверка TOCTOU в /transfer на ЛОКАЛЬНОМ стенде: N одновременных переводов полного баланса.
Ожидаемо при корректной логике: ровно 1 успех и баланс 0. Запуск: python race_check.py <api> <rounds> <n>"""
import asyncio, subprocess, sys
import httpx

API, ROUNDS, N = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
PSQL = ["psql", "-h", "127.0.0.1", "-p", "55432", "-U", "postgres", "bank", "-At", "-c"]


def sql(q):
    return subprocess.run(PSQL + [q], capture_output=True, text=True).stdout.strip()


async def main():
    body = {"from_account_id": 3, "to_account_id": 2, "amount_cents": 10000}
    hdr = {"X-User-Id": "3"}
    limits = httpx.Limits(max_connections=N)
    async with httpx.AsyncClient(base_url=API, limits=limits, timeout=30) as c:
        for rnd in range(1, ROUNDS + 1):
            sql("update accounts set balance_cents=10000 where id=3")
            before = int(sql("select count(*) from transactions where from_account_id=3"))
            codes = await asyncio.gather(*[c.post("/transfer", json=body, headers=hdr) for _ in range(N)])
            ok = sum(r.status_code == 200 for r in codes)
            bal = sql("select balance_cents from accounts where id=3")
            after = int(sql("select count(*) from transactions where from_account_id=3"))
            print(f"round {rnd}: HTTP200={ok}/{N}, new tx rows={after - before}, balance_cents={bal}")


asyncio.run(main())

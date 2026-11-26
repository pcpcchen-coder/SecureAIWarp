"""SQLite 資料儲存。"""
from __future__ import annotations

import sqlite3
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,          -- YYYY-MM-DD
    amount REAL NOT NULL,
    currency TEXT NOT NULL,      -- ISO 4217, e.g. JPY
    category TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    twd_rate REAL,               -- 記帳當時 1 單位外幣 = 多少 TWD；NULL 表示尚未換算
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_expenses_date ON expenses(date);
"""


class Store:
    def __init__(self, db_path: str):
        self.db_path = db_path
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(r) -> dict:
        d = dict(r)
        d["twd_amount"] = round(d["amount"] * d["twd_rate"], 2) if d["twd_rate"] is not None else None
        return d

    def add(self, date: str, amount: float, currency: str, category: str,
            note: str, twd_rate: Optional[float]) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO expenses (date, amount, currency, category, note, twd_rate) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (date, amount, currency, category, note, twd_rate))
            return cur.lastrowid

    def delete(self, expense_id: int) -> bool:
        with self._conn() as conn:
            return conn.execute("DELETE FROM expenses WHERE id=?", (expense_id,)).rowcount > 0

    def list(self, month: Optional[str] = None, category: Optional[str] = None) -> list[dict]:
        sql, args = "SELECT * FROM expenses WHERE 1=1", []
        if month:
            sql += " AND substr(date, 1, 7) = ?"
            args.append(month)
        if category:
            sql += " AND category = ?"
            args.append(category)
        sql += " ORDER BY date DESC, id DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, args)]

    def unconverted(self) -> list[dict]:
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(
                "SELECT * FROM expenses WHERE twd_rate IS NULL")]

    def set_rate(self, expense_id: int, twd_rate: float):
        with self._conn() as conn:
            conn.execute("UPDATE expenses SET twd_rate=? WHERE id=?", (twd_rate, expense_id))

    def months(self) -> list[str]:
        with self._conn() as conn:
            return [r[0] for r in conn.execute(
                "SELECT DISTINCT substr(date, 1, 7) FROM expenses ORDER BY 1 DESC")]

    def categories(self) -> list[str]:
        with self._conn() as conn:
            return [r[0] for r in conn.execute(
                "SELECT DISTINCT category FROM expenses ORDER BY 1")]


def summarize(rows: list[dict]) -> dict:
    """依月份、類別、月份×類別加總台幣金額。未換算的筆數另外計算。"""
    by_month: dict[str, float] = {}
    by_category: dict[str, float] = {}
    by_month_category: dict[tuple, float] = {}
    total, pending = 0.0, 0
    for r in rows:
        if r["twd_amount"] is None:
            pending += 1
            continue
        m, c, v = r["date"][:7], r["category"], r["twd_amount"]
        by_month[m] = by_month.get(m, 0.0) + v
        by_category[c] = by_category.get(c, 0.0) + v
        by_month_category[(m, c)] = by_month_category.get((m, c), 0.0) + v
        total += v
    rnd = lambda d: {k: round(v, 2) for k, v in d.items()}
    return {
        "total": round(total, 2),
        "pending": pending,
        "by_month": dict(sorted(rnd(by_month).items(), reverse=True)),
        "by_category": dict(sorted(rnd(by_category).items(), key=lambda kv: -kv[1])),
        "by_month_category": [
            {"month": m, "category": c, "twd": v}
            for (m, c), v in sorted(
                sorted(rnd(by_month_category).items(), key=lambda kv: -kv[1]),
                key=lambda kv: kv[0][0], reverse=True)  # 月份新到舊，同月金額大到小
        ],
    }

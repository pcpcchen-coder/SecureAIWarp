"""Flask 網頁應用：新增、列表、統計、匯出 CSV。"""
from __future__ import annotations

import csv
import io
import os
import re
import secrets
from datetime import date as date_cls, datetime
from pathlib import Path

from flask import (Flask, Response, abort, flash, redirect, render_template,
                   request, session, url_for)

from .rates import RateError, RateProvider, http_get_json
from .storage import Store, summarize

APP_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB = APP_DIR / "data" / "expenses.db"

CATEGORIES = ["餐飲", "交通", "住宿", "購物", "娛樂", "門票", "通訊", "醫療", "其他"]
CURRENCIES = ["TWD", "USD", "JPY", "KRW", "EUR", "GBP", "CNY", "HKD", "SGD",
              "THB", "VND", "MYR", "PHP", "IDR", "AUD", "NZD", "CAD", "CHF"]
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


def load_dotenv(path: Path) -> dict:
    """讀取簡單的 KEY=VALUE 格式 .env 檔（不覆蓋已存在的環境變數）。"""
    values = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip().strip('"').strip("'")
    return values


def create_app(db_path=None, api_key=None, fetch=None, testing=False) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = testing
    app.secret_key = secrets.token_hex(32)

    if api_key is None and not testing:
        env = load_dotenv(APP_DIR / ".env")
        api_key = os.environ.get("EXCHANGERATE_API_KEY") or env.get("EXCHANGERATE_API_KEY")
    db_path = str(db_path or os.environ.get("EXPENSES_DB") or DEFAULT_DB)
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    store = Store(db_path)
    rates = RateProvider(db_path, api_key, fetch=fetch or http_get_json)
    app.extensions["store"] = store
    app.extensions["rates"] = rates

    # --- CSRF：所有 POST 都要帶 session 中的 token，避免其他網站偷偷對 localhost 送表單 ---
    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def check_csrf():
        if request.method == "POST":
            sent = request.form.get("csrf", "")
            if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
                abort(400, "CSRF token 無效，請重新整理頁面")

    def fmt(v):
        return "—" if v is None else f"{v:,.2f}"

    app.jinja_env.filters["money"] = fmt

    # --- routes ---
    @app.get("/")
    def index():
        month = request.args.get("month") or None
        category = request.args.get("category") or None
        if month and not MONTH_RE.match(month):
            month = None
        rows = store.list(month=month, category=category)
        return render_template(
            "index.html", rows=rows, summary=summarize(rows),
            months=store.months(), used_categories=store.categories(),
            categories=CATEGORIES, currencies=CURRENCIES,
            month=month, category=category, today=date_cls.today().isoformat(),
            rate_status=rates.status(), pending_total=len(store.unconverted()))

    @app.post("/expenses")
    def add_expense():
        f = request.form
        errors = []
        try:
            amount = float(f.get("amount", ""))
            if not (amount > 0) or amount > 1e12:
                raise ValueError
            amount = round(amount, 4)
        except ValueError:
            errors.append("金額必須是大於 0 的數字")
        currency = f.get("currency", "").strip().upper()
        if not CURRENCY_RE.match(currency):
            errors.append("幣別必須是 3 個英文字母的代碼（例如 JPY）")
        category = f.get("category", "").strip()[:50]
        if not category:
            errors.append("請選擇類別")
        note = f.get("note", "").strip()[:500]
        d = f.get("date", "").strip()
        try:
            datetime.strptime(d, "%Y-%m-%d")
        except ValueError:
            errors.append("日期格式必須是 YYYY-MM-DD")
        if errors:
            for e in errors:
                flash(e, "error")
            return redirect(url_for("index"))

        try:
            rate = rates.twd_per_unit(currency)
        except RateError as e:
            rate = None
            flash(f"已儲存，但暫時無法換算台幣：{e}。之後可按「重新換算」。", "warn")
        store.add(d, amount, currency, category, note, rate)
        if rate is not None:
            flash("已新增", "ok")
        return redirect(url_for("index"))

    @app.post("/expenses/<int:expense_id>/delete")
    def delete_expense(expense_id):
        if not store.delete(expense_id):
            abort(404)
        flash("已刪除", "ok")
        return redirect(request.referrer or url_for("index"))

    @app.post("/reconvert")
    def reconvert():
        """替尚未換算的紀錄補上匯率（使用目前匯率）。"""
        done, failed = 0, []
        for r in store.unconverted():
            try:
                store.set_rate(r["id"], rates.twd_per_unit(r["currency"]))
                done += 1
            except RateError as e:
                failed.append(str(e))
        if done:
            flash(f"已換算 {done} 筆", "ok")
        if failed:
            flash(f"{len(failed)} 筆無法換算：{failed[0]}", "warn")
        if not done and not failed:
            flash("沒有需要換算的紀錄", "ok")
        return redirect(url_for("index"))

    @app.get("/export.csv")
    def export_csv():
        month = request.args.get("month") or None
        if month and not MONTH_RE.match(month):
            month = None
        rows = store.list(month=month, category=request.args.get("category") or None)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "date", "amount", "currency", "category", "note",
                    "twd_rate", "twd_amount"])
        for r in rows:
            w.writerow([r["id"], r["date"], r["amount"], r["currency"],
                        _csv_safe(r["category"]), _csv_safe(r["note"]),
                        "" if r["twd_rate"] is None else round(r["twd_rate"], 6),
                        "" if r["twd_amount"] is None else r["twd_amount"]])
        name = f"expenses-{month or 'all'}.csv"
        # 加 UTF-8 BOM，讓 Excel 正確顯示中文
        return Response("﻿" + buf.getvalue(), mimetype="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    return app


def _csv_safe(s: str) -> str:
    """避免 CSV 公式注入（以 = + - @ 開頭的字串在 Excel 會被當成公式）。"""
    if s and s[0] in "=+-@\t\r":
        return "'" + s
    return s

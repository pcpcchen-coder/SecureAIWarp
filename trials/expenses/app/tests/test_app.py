import csv
import io
import re

import pytest

from expenses import rates as rates_mod
from expenses.app import create_app, load_dotenv
from expenses.rates import RateError, RateProvider, build_url
from expenses.storage import Store, summarize

# 依照 exchangerate-api.com v6 /latest/TWD 真實回應格式的假資料
FAKE_OK = {
    "result": "success",
    "documentation": "https://www.exchangerate-api.com/docs",
    "terms_of_use": "https://www.exchangerate-api.com/terms",
    "time_last_update_unix": 1764115201,
    "time_last_update_utc": "Wed, 26 Nov 2025 00:00:01 +0000",
    "time_next_update_unix": 1764201601,
    "time_next_update_utc": "Thu, 27 Nov 2025 00:00:01 +0000",
    "base_code": "TWD",
    "conversion_rates": {"TWD": 1, "USD": 0.03125, "JPY": 5.0, "EUR": 0.025},
}


class FakeFetch:
    def __init__(self, response=FAKE_OK, exc=None):
        self.response, self.exc, self.urls = response, exc, []

    def __call__(self, url):
        self.urls.append(url)
        if self.exc:
            raise self.exc
        return self.response


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "t.db")


def make_client(db, fetch=None, api_key="test-key"):
    app = create_app(db_path=db, api_key=api_key, fetch=fetch or FakeFetch(), testing=True)
    return app, app.test_client()


def token(client):
    html = client.get("/").get_data(as_text=True)
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def add(client, tok, **kw):
    data = {"date": "2025-11-03", "amount": "1000", "currency": "JPY",
            "category": "餐飲", "note": "拉麵", "csrf": tok}
    data.update(kw)
    return client.post("/expenses", data=data, follow_redirects=True)


# ---------- rates ----------

def test_build_url_matches_v6_format():
    assert build_url("abc123") == "https://v6.exchangerate-api.com/v6/abc123/latest/TWD"


def test_twd_per_unit_conversion(db):
    rp = RateProvider(db, "k", fetch=FakeFetch())
    assert rp.twd_per_unit("JPY") == pytest.approx(0.2)
    assert rp.twd_per_unit("usd") == pytest.approx(32.0)
    assert rp.twd_per_unit("TWD") == 1.0


def test_twd_needs_no_key_or_network(db):
    f = FakeFetch()
    rp = RateProvider(db, None, fetch=f)
    assert rp.twd_per_unit("TWD") == 1.0
    assert f.urls == []


def test_rates_are_cached(db):
    f = FakeFetch()
    rp = RateProvider(db, "k", fetch=f)
    rp.twd_per_unit("JPY"); rp.twd_per_unit("USD")
    assert len(f.urls) == 1


def test_cache_expires_and_refetches(db):
    now = [1000.0]
    f = FakeFetch()
    rp = RateProvider(db, "k", fetch=f, ttl=60, clock=lambda: now[0])
    rp.get_rates()
    now[0] += 61
    rp.get_rates()
    assert len(f.urls) == 2


def test_stale_cache_used_when_fetch_fails(db):
    now = [1000.0]
    RateProvider(db, "k", fetch=FakeFetch(), ttl=60, clock=lambda: now[0]).get_rates()
    now[0] += 10_000
    rp = RateProvider(db, "k", fetch=FakeFetch(exc=RateError("offline")), ttl=60, clock=lambda: now[0])
    assert rp.twd_per_unit("JPY") == pytest.approx(0.2)


def test_missing_key_raises(db):
    with pytest.raises(RateError, match="EXCHANGERATE_API_KEY"):
        RateProvider(db, "", fetch=FakeFetch()).twd_per_unit("JPY")


def test_api_error_response(db):
    f = FakeFetch(response={"result": "error", "error-type": "invalid-key"})
    with pytest.raises(RateError, match="invalid-key"):
        RateProvider(db, "bad", fetch=f).twd_per_unit("JPY")


def test_unsupported_currency(db):
    with pytest.raises(RateError, match="XYZ"):
        RateProvider(db, "k", fetch=FakeFetch()).twd_per_unit("XYZ")


def test_http_get_json_network_failure_is_rateerror(monkeypatch):
    import urllib.error
    def boom(*a, **k):
        raise urllib.error.URLError("no network")
    monkeypatch.setattr(rates_mod.urllib.request, "urlopen", boom)
    with pytest.raises(RateError, match="無法連線"):
        rates_mod.http_get_json("https://v6.exchangerate-api.com/v6/k/latest/TWD")


# ---------- storage / summary ----------

def test_summarize_groups_by_month_and_category():
    rows = [
        {"date": "2025-10-01", "category": "餐飲", "twd_amount": 100.0},
        {"date": "2025-10-15", "category": "交通", "twd_amount": 50.0},
        {"date": "2025-11-02", "category": "餐飲", "twd_amount": 30.0},
        {"date": "2025-11-03", "category": "餐飲", "twd_amount": None},
    ]
    s = summarize(rows)
    assert s["total"] == 180.0
    assert s["pending"] == 1
    assert s["by_month"] == {"2025-11": 30.0, "2025-10": 150.0}
    assert s["by_category"] == {"餐飲": 130.0, "交通": 50.0}
    assert s["by_month_category"][0] == {"month": "2025-11", "category": "餐飲", "twd": 30.0}


def test_data_persists_across_restart(db):
    _, c = make_client(db)
    add(c, token(c))
    _, c2 = make_client(db)  # 模擬關掉重開
    html = c2.get("/").get_data(as_text=True)
    assert "拉麵" in html and "200.00" in html


# ---------- web ----------

def test_add_and_list_with_twd(db):
    _, c = make_client(db)
    html = add(c, token(c)).get_data(as_text=True)
    assert "已新增" in html
    assert "1,000.00 JPY" in html
    assert "200.00" in html


def test_add_validation(db):
    _, c = make_client(db)
    html = add(c, token(c), amount="-5", date="2025/11/01").get_data(as_text=True)
    assert "金額必須是大於 0" in html and "日期格式" in html
    assert "還沒有紀錄" in html


def test_csrf_required(db):
    _, c = make_client(db)
    r = c.post("/expenses", data={"date": "2025-11-01", "amount": "1", "currency": "TWD", "category": "餐飲"})
    assert r.status_code == 400


def test_add_without_key_saves_then_reconvert(db):
    app, c = make_client(db, api_key="")
    html = add(c, token(c)).get_data(as_text=True)
    assert "暫時無法換算" in html and "尚未換算" in html
    # 之後設定金鑰（例如回到有網路的地方）再重新換算
    app.extensions["rates"].api_key = "k"
    html = c.post("/reconvert", data={"csrf": token(c)}, follow_redirects=True).get_data(as_text=True)
    assert "已換算 1 筆" in html and "200.00" in html


def test_rate_frozen_at_entry_time(db):
    app, c = make_client(db)
    add(c, token(c))
    store = app.extensions["store"]
    assert store.list()[0]["twd_amount"] == 200.0
    # 匯率改變不影響既有紀錄
    app.extensions["rates"].fetch = FakeFetch({**FAKE_OK, "conversion_rates": {"JPY": 4.0}})
    app.extensions["rates"].get_rates(force=True)
    assert store.list()[0]["twd_amount"] == 200.0


def test_filter_by_month_and_category(db):
    _, c = make_client(db)
    t = token(c)
    add(c, t, date="2025-10-05", note="十月", category="交通")
    add(c, t, date="2025-11-05", note="十一月")
    html = c.get("/?month=2025-10").get_data(as_text=True)
    assert "十月" in html and "十一月" not in html
    html = c.get("/?category=餐飲").get_data(as_text=True)
    assert "十一月" in html and "十月" not in html


def test_delete(db):
    app, c = make_client(db)
    t = token(c)
    add(c, t)
    eid = app.extensions["store"].list()[0]["id"]
    c.post(f"/expenses/{eid}/delete", data={"csrf": t})
    assert app.extensions["store"].list() == []
    assert c.post("/expenses/9999/delete", data={"csrf": t}).status_code == 404


def test_export_csv(db):
    _, c = make_client(db)
    t = token(c)
    add(c, t)
    add(c, t, amount="100", currency="TWD", note="=HYPERLINK(\"x\")")
    r = c.get("/export.csv")
    assert r.mimetype == "text/csv"
    assert "attachment" in r.headers["Content-Disposition"]
    text = r.get_data(as_text=True)
    assert text.startswith("﻿")
    rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
    assert len(rows) == 2
    jpy = next(x for x in rows if x["currency"] == "JPY")
    assert jpy["twd_amount"] == "200.0" and jpy["note"] == "拉麵"
    twd = next(x for x in rows if x["currency"] == "TWD")
    assert twd["note"].startswith("'=")  # 防 CSV 公式注入


def test_export_csv_month_filter(db):
    _, c = make_client(db)
    t = token(c)
    add(c, t, date="2025-10-05")
    add(c, t, date="2025-11-05")
    text = c.get("/export.csv?month=2025-10").get_data(as_text=True)
    assert text.count("\n") == 2


def test_html_escapes_note(db):
    _, c = make_client(db)
    html = add(c, token(c), note="<script>alert(1)</script>").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html


def test_load_dotenv(tmp_path):
    p = tmp_path / ".env"
    p.write_text("# comment\nEXCHANGERATE_API_KEY=\"abc\"\nOTHER=1\n", encoding="utf-8")
    assert load_dotenv(p)["EXCHANGERATE_API_KEY"] == "abc"
    assert load_dotenv(tmp_path / "missing") == {}

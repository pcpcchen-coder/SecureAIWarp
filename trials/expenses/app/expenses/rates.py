"""匯率取得與快取：使用 exchangerate-api.com v6 API。

API 格式（Standard endpoint）：
    GET https://v6.exchangerate-api.com/v6/<API_KEY>/latest/TWD
成功回應：
    {"result": "success", "base_code": "TWD",
     "time_last_update_unix": 1700000000,
     "conversion_rates": {"TWD": 1, "USD": 0.0312, "JPY": 4.71, ...}}
失敗回應：
    {"result": "error", "error-type": "invalid-key"}

conversion_rates[X] 代表「1 TWD = 多少 X」，所以 X 幣金額換成台幣 = amount / rate[X]。
"""
from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Optional

API_BASE = "https://v6.exchangerate-api.com/v6"
BASE_CURRENCY = "TWD"
CACHE_TTL_SECONDS = 6 * 3600
HTTP_TIMEOUT = 10


class RateError(Exception):
    """無法取得匯率（沒有金鑰、網路錯誤、API 回傳錯誤、不支援的幣別）。"""


def build_url(api_key: str, base: str = BASE_CURRENCY) -> str:
    return f"{API_BASE}/{urllib.parse.quote(api_key, safe='')}/latest/{base}"


def http_get_json(url: str) -> dict:
    """預設的 HTTP 取得函式（只用標準函式庫）。測試時會替換掉。"""
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "expenses-app/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # API 在錯誤時（例如金鑰無效）也會回 JSON 本文
        try:
            return json.loads(e.read().decode("utf-8"))
        except Exception:
            raise RateError(f"匯率 API HTTP 錯誤 {e.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RateError(f"無法連線到匯率 API：{getattr(e, 'reason', e)}") from None
    except ValueError:
        raise RateError("匯率 API 回應不是有效的 JSON") from None


class RateProvider:
    def __init__(self, db_path: str, api_key: Optional[str],
                 fetch: Callable[[str], dict] = http_get_json,
                 ttl: int = CACHE_TTL_SECONDS,
                 clock: Callable[[], float] = time.time):
        self.db_path = db_path
        self.api_key = (api_key or "").strip() or None
        self.fetch = fetch
        self.ttl = ttl
        self.clock = clock

    # --- cache ---
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""CREATE TABLE IF NOT EXISTS rate_cache (
            base TEXT PRIMARY KEY, fetched_at REAL NOT NULL,
            updated_unix INTEGER, rates_json TEXT NOT NULL)""")
        return conn

    def _load_cache(self):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT fetched_at, updated_unix, rates_json FROM rate_cache WHERE base=?",
                (BASE_CURRENCY,)).fetchone()
        if not row:
            return None
        return {"fetched_at": row[0], "updated_unix": row[1], "rates": json.loads(row[2])}

    def _save_cache(self, rates: dict, updated_unix):
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO rate_cache (base, fetched_at, updated_unix, rates_json) "
                "VALUES (?, ?, ?, ?)",
                (BASE_CURRENCY, self.clock(), updated_unix, json.dumps(rates)))

    # --- fetching ---
    def _fetch_remote(self) -> dict:
        if not self.api_key:
            raise RateError("尚未設定 EXCHANGERATE_API_KEY")
        data = self.fetch(build_url(self.api_key))
        if not isinstance(data, dict):
            raise RateError("匯率 API 回應格式錯誤")
        if data.get("result") != "success":
            raise RateError(f"匯率 API 錯誤：{data.get('error-type', 'unknown')}")
        rates = data.get("conversion_rates")
        if not isinstance(rates, dict) or not rates:
            raise RateError("匯率 API 回應缺少 conversion_rates")
        self._save_cache(rates, data.get("time_last_update_unix"))
        return rates

    def get_rates(self, force: bool = False) -> dict:
        """回傳以 TWD 為基準的匯率表。快取有效就用快取；抓取失敗時退回舊快取。"""
        cache = self._load_cache()
        if cache and not force and self.clock() - cache["fetched_at"] < self.ttl:
            return cache["rates"]
        try:
            return self._fetch_remote()
        except RateError:
            if cache:
                return cache["rates"]
            raise

    def status(self) -> dict:
        cache = self._load_cache()
        return {"has_key": bool(self.api_key),
                "cached_at": cache["fetched_at"] if cache else None,
                "updated_unix": cache["updated_unix"] if cache else None}

    def twd_per_unit(self, currency: str) -> float:
        """1 單位 currency 等於多少台幣。"""
        currency = currency.upper()
        if currency == BASE_CURRENCY:
            return 1.0
        rates = self.get_rates()
        rate = rates.get(currency)
        if not rate:
            raise RateError(f"不支援的幣別：{currency}")
        return 1.0 / float(rate)

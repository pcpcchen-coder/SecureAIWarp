"""Open-Meteo API 用戶端（只用標準函式庫）。

用到兩個服務：
- 地名查詢 Geocoding API：https://geocoding-api.open-meteo.com/v1/search
- 天氣預報 Forecast API： https://api.open-meteo.com/v1/forecast
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Callable, Optional

from . import __version__
from .aliases import resolve as resolve_alias
from .cache import FileCache

GEOCODING_URL = "https://geocoding-api.open-meteo.com/v1/search"
FORECAST_URL = "https://api.open-meteo.com/v1/forecast"

GEOCODE_TTL = 24 * 3600  # 地名對應座標很少變，快取一天
FORECAST_TTL = 10 * 60   # 天氣資料快取 10 分鐘

CURRENT_FIELDS = [
    "temperature_2m",
    "relative_humidity_2m",
    "apparent_temperature",
    "precipitation",
    "weather_code",
    "wind_speed_10m",
]
DAILY_FIELDS = [
    "weather_code",
    "temperature_2m_max",
    "temperature_2m_min",
    "precipitation_probability_max",
]


class WeatherError(Exception):
    """給使用者看的錯誤（網路錯誤、找不到城市、API 回傳錯誤等）。"""


class CityNotFound(WeatherError):
    pass


@dataclass
class Location:
    name: str
    latitude: float
    longitude: float
    country: str = ""
    admin1: str = ""
    timezone: str = "auto"

    @property
    def label(self) -> str:
        parts = [self.name]
        if self.admin1 and self.admin1 != self.name:
            parts.append(self.admin1)
        if self.country:
            parts.append(self.country)
        return ", ".join(parts)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Location":
        return cls(
            name=d["name"],
            latitude=float(d["latitude"]),
            longitude=float(d["longitude"]),
            country=d.get("country", "") or "",
            admin1=d.get("admin1", "") or "",
            timezone=d.get("timezone", "auto") or "auto",
        )


Fetcher = Callable[[str], Any]


def http_get_json(url: str, timeout: float = 10.0) -> Any:
    """實際發出 HTTP GET 並解析 JSON。測試時會被替換掉。"""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"weather-cli/{__version__}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # Open-Meteo 出錯時會回 {"error": true, "reason": "..."}
        reason = ""
        try:
            body = json.loads(e.read().decode("utf-8"))
            reason = body.get("reason", "")
        except Exception:
            pass
        raise WeatherError(f"API 回傳錯誤 HTTP {e.code}" + (f"：{reason}" if reason else "")) from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise WeatherError(f"無法連線到 {urllib.parse.urlsplit(url).netloc}：{e}") from e
    except json.JSONDecodeError as e:
        raise WeatherError("API 回傳的資料不是有效的 JSON") from e


def build_url(base: str, params: dict) -> str:
    return base + "?" + urllib.parse.urlencode(params)


class OpenMeteoClient:
    def __init__(self, cache: Optional[FileCache] = None, fetch: Fetcher = http_get_json,
                 use_cache: bool = True, language: str = "zh"):
        self.cache = cache
        self.fetch = fetch
        self.use_cache = use_cache and cache is not None
        self.language = language

    def _get(self, url: str, ttl: float) -> Any:
        if self.use_cache:
            hit = self.cache.get(url, ttl)
            if hit is not None:
                return hit
        data = self.fetch(url)
        if isinstance(data, dict) and data.get("error"):
            raise WeatherError(f"API 回傳錯誤：{data.get('reason', '未知原因')}")
        if self.cache is not None:
            self.cache.set(url, data)
        return data

    def geocode(self, name: str) -> Location:
        name = name.strip()
        if not name:
            raise CityNotFound("請輸入城市名稱")
        url = build_url(GEOCODING_URL, {
            "name": resolve_alias(name),
            "count": 1,
            "language": self.language,
            "format": "json",
        })
        data = self._get(url, GEOCODE_TTL)
        results = (data or {}).get("results") or []
        if not results:
            raise CityNotFound(f"找不到城市「{name}」")
        r = results[0]
        return Location(
            name=r.get("name", name),
            latitude=r["latitude"],
            longitude=r["longitude"],
            country=r.get("country", "") or "",
            admin1=r.get("admin1", "") or "",
            timezone=r.get("timezone", "auto") or "auto",
        )

    def forecast(self, loc: Location, days: int = 3) -> dict:
        # forecast_days 包含今天，所以要多抓一天才有「未來三天」
        url = build_url(FORECAST_URL, {
            "latitude": f"{loc.latitude:.4f}",
            "longitude": f"{loc.longitude:.4f}",
            "current": ",".join(CURRENT_FIELDS),
            "daily": ",".join(DAILY_FIELDS),
            "timezone": loc.timezone or "auto",
            "forecast_days": days + 1,
        })
        data = self._get(url, FORECAST_TTL)
        if not isinstance(data, dict) or "current" not in data or "daily" not in data:
            raise WeatherError("API 回傳的天氣資料格式不正確")
        return data

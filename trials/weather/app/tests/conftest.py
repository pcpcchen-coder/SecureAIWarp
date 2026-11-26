"""測試共用設定：所有檔案寫到暫存目錄，且絕不連真實網路。"""

import urllib.parse

import pytest

# 依照 Open-Meteo 真實回應格式製作的假資料
GEOCODE_TAIPEI = {
    "results": [{
        "id": 1668341, "name": "臺北市", "latitude": 25.04776, "longitude": 121.53185,
        "elevation": 9.0, "feature_code": "PPLC", "country_code": "TW",
        "timezone": "Asia/Taipei", "country": "臺灣", "admin1": "臺北市",
    }],
    "generationtime_ms": 0.5,
}
GEOCODE_TOKYO = {
    "results": [{
        "id": 1850147, "name": "東京", "latitude": 35.6895, "longitude": 139.69171,
        "country_code": "JP", "timezone": "Asia/Tokyo", "country": "日本", "admin1": "東京都",
    }],
}
GEOCODE_EMPTY = {"generationtime_ms": 0.3}  # 找不到時 Open-Meteo 不會回傳 results 欄位


def make_forecast(tz="Asia/Taipei"):
    return {
        "latitude": 25.0, "longitude": 121.5, "timezone": tz,
        "current_units": {"time": "iso8601", "interval": "seconds",
                          "temperature_2m": "°C", "relative_humidity_2m": "%",
                          "apparent_temperature": "°C", "precipitation": "mm",
                          "weather_code": "wmo code", "wind_speed_10m": "km/h"},
        "current": {"time": "2026-11-26T14:00", "interval": 900,
                    "temperature_2m": 23.4, "relative_humidity_2m": 71,
                    "apparent_temperature": 24.1, "precipitation": 0.0,
                    "weather_code": 2, "wind_speed_10m": 9.7},
        "daily_units": {"time": "iso8601", "weather_code": "wmo code",
                        "temperature_2m_max": "°C", "temperature_2m_min": "°C",
                        "precipitation_probability_max": "%"},
        "daily": {"time": ["2026-11-26", "2026-11-27", "2026-11-28", "2026-11-29"],
                  "weather_code": [2, 61, 3, 0],
                  "temperature_2m_max": [25.1, 22.0, 21.4, 24.8],
                  "temperature_2m_min": [19.0, 18.2, 17.5, 18.9],
                  "precipitation_probability_max": [10, 80, 35, 5]},
    }


class FakeFetch:
    """取代真實 HTTP：依網址回傳假資料，並記錄呼叫次數。"""

    def __init__(self):
        self.calls = []
        self.geo = {"Taipei": GEOCODE_TAIPEI, "Tokyo": GEOCODE_TOKYO}

    def __call__(self, url):
        self.calls.append(url)
        parts = urllib.parse.urlsplit(url)
        q = dict(urllib.parse.parse_qsl(parts.query))
        if parts.netloc == "geocoding-api.open-meteo.com":
            return self.geo.get(q["name"], GEOCODE_EMPTY)
        if parts.netloc == "api.open-meteo.com":
            return make_forecast(q.get("timezone", "auto"))
        raise AssertionError(f"unexpected url {url}")

    def hosts(self):
        return [urllib.parse.urlsplit(u).netloc for u in self.calls]


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("WEATHER_HOME", str(tmp_path / "home"))

    def no_network(*a, **k):
        raise AssertionError("測試不應連到真實網路")

    monkeypatch.setattr("urllib.request.urlopen", no_network)
    return tmp_path / "home"


@pytest.fixture
def fake():
    return FakeFetch()

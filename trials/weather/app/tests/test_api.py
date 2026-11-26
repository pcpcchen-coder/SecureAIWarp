import io
import json
import urllib.error
import urllib.parse

import pytest

from weather_cli import api
from weather_cli.api import (CityNotFound, Location, OpenMeteoClient, WeatherError,
                             http_get_json)
from weather_cli.cache import FileCache


def qs(url):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))


def test_geocode_builds_real_api_url_and_parses(fake):
    c = OpenMeteoClient(fetch=fake)
    loc = c.geocode("台北")
    url = fake.calls[0]
    assert url.startswith("https://geocoding-api.open-meteo.com/v1/search?")
    assert qs(url) == {"name": "Taipei", "count": "1", "language": "zh", "format": "json"}
    assert loc.name == "臺北市"
    assert loc.timezone == "Asia/Taipei"
    assert loc.latitude == pytest.approx(25.04776)


@pytest.mark.parametrize("name", ["台北", "臺北", "台北市", "臺北市", "Taipei"])
def test_chinese_aliases_resolve(fake, name):
    loc = OpenMeteoClient(fetch=fake).geocode(name)
    assert qs(fake.calls[0])["name"] == "Taipei"
    assert loc.name == "臺北市"


def test_unaliased_name_sent_as_is(fake):
    with pytest.raises(CityNotFound):
        OpenMeteoClient(fetch=fake).geocode("Reykjavik")
    assert qs(fake.calls[0])["name"] == "Reykjavik"


def test_geocode_not_found(fake):
    with pytest.raises(CityNotFound):
        OpenMeteoClient(fetch=fake).geocode("不存在的地方")


def test_geocode_empty_name(fake):
    with pytest.raises(CityNotFound):
        OpenMeteoClient(fetch=fake).geocode("   ")
    assert fake.calls == []


def test_forecast_url_params(fake):
    loc = Location("臺北市", 25.04776, 121.53185, timezone="Asia/Taipei")
    data = OpenMeteoClient(fetch=fake).forecast(loc)
    url = fake.calls[0]
    assert url.startswith("https://api.open-meteo.com/v1/forecast?")
    q = qs(url)
    assert q["latitude"] == "25.0478" and q["longitude"] == "121.5319"
    assert q["forecast_days"] == "4"
    assert q["timezone"] == "Asia/Taipei"
    assert "weather_code" in q["current"].split(",")
    assert set(q["daily"].split(",")) >= {"temperature_2m_max", "temperature_2m_min"}
    assert data["current"]["temperature_2m"] == 23.4


def test_api_error_payload_raises():
    def fetch(url):
        return {"error": True, "reason": "Latitude must be in range of -90 to 90°."}
    with pytest.raises(WeatherError, match="Latitude"):
        OpenMeteoClient(fetch=fetch).forecast(Location("x", 999, 0))


def test_malformed_forecast_raises():
    with pytest.raises(WeatherError):
        OpenMeteoClient(fetch=lambda u: {"foo": 1}).forecast(Location("x", 1, 1))


def test_cache_prevents_repeat_calls(fake, tmp_path):
    cache = FileCache(tmp_path / "c.json")
    c = OpenMeteoClient(cache=cache, fetch=fake)
    loc = c.geocode("台北")
    c.forecast(loc)
    c2 = OpenMeteoClient(cache=cache, fetch=fake)  # 模擬下一次執行程式
    c2.forecast(c2.geocode("台北"))
    assert len(fake.calls) == 2


def test_cache_expires(fake, tmp_path):
    now = [1000.0]
    cache = FileCache(tmp_path / "c.json", clock=lambda: now[0])
    c = OpenMeteoClient(cache=cache, fetch=fake)
    loc = Location("臺北市", 25.0, 121.5)
    c.forecast(loc)
    now[0] += api.FORECAST_TTL - 1
    c.forecast(loc)
    assert len(fake.calls) == 1
    now[0] += 2
    c.forecast(loc)
    assert len(fake.calls) == 2


def test_no_cache_option_bypasses_cache(fake, tmp_path):
    cache = FileCache(tmp_path / "c.json")
    OpenMeteoClient(cache=cache, fetch=fake).geocode("台北")
    OpenMeteoClient(cache=cache, fetch=fake, use_cache=False).geocode("台北")
    assert len(fake.calls) == 2


def test_error_responses_are_not_cached(tmp_path):
    cache = FileCache(tmp_path / "c.json")
    calls = []

    def fetch(url):
        calls.append(url)
        return {"error": True, "reason": "boom"}
    c = OpenMeteoClient(cache=cache, fetch=fetch)
    for _ in range(2):
        with pytest.raises(WeatherError):
            c.geocode("台北")
    assert len(calls) == 2


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def test_http_get_json_success(monkeypatch):
    seen = {}

    def urlopen(req, timeout):
        seen["ua"] = req.get_header("User-agent")
        seen["url"] = req.full_url
        return FakeResp(json.dumps({"ok": 1}).encode())
    monkeypatch.setattr(api.urllib.request, "urlopen", urlopen)
    assert http_get_json("https://api.open-meteo.com/v1/forecast?x=1") == {"ok": 1}
    assert seen["ua"].startswith("weather-cli/")


def test_http_get_json_http_error_reason(monkeypatch):
    def urlopen(req, timeout):
        body = io.BytesIO(json.dumps({"error": True, "reason": "Bad param"}).encode())
        raise urllib.error.HTTPError(req.full_url, 400, "Bad Request", {}, body)
    monkeypatch.setattr(api.urllib.request, "urlopen", urlopen)
    with pytest.raises(WeatherError, match="400.*Bad param"):
        http_get_json("https://api.open-meteo.com/v1/forecast")


def test_http_get_json_network_error(monkeypatch):
    def urlopen(req, timeout):
        raise urllib.error.URLError("no route")
    monkeypatch.setattr(api.urllib.request, "urlopen", urlopen)
    with pytest.raises(WeatherError, match="api.open-meteo.com"):
        http_get_json("https://api.open-meteo.com/v1/forecast")

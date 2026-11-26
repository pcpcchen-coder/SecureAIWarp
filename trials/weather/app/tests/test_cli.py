import io
import json

from weather_cli.cli import main
from weather_cli.format import describe, render
from weather_cli.api import Location
from conftest import make_forecast


def run(argv, fake):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, fetch=fake, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_query_city_shows_current_and_three_days(fake):
    code, out, _ = run(["台北"], fake)
    assert code == 0
    assert "臺北市" in out
    assert "23.4°C" in out and "局部多雲" in out
    # 今天（11/26）不列在未來三天，列 27、28、29
    assert "11/26（" not in out
    for d, desc in [("11/27（五）", "小雨"), ("11/28（六）", "陰天"), ("11/29（日）", "晴朗")]:
        assert d in out and desc in out
    assert "降雨機率 80%" in out


def test_multiword_city_joined(fake):
    run(["New", "York"], fake)
    assert "name=New+York" in fake.calls[0]


def test_unknown_city_error(fake):
    code, out, err = run(["火星城"], fake)
    assert code == 1
    assert "找不到城市" in err


def test_no_args_without_favorites_shows_hint(fake):
    code, out, _ = run([], fake)
    assert code == 0
    assert "--add" in out
    assert fake.calls == []


def test_add_list_and_show_favorites(fake, isolated_home):
    assert run(["--add", "台北"], fake)[0] == 0
    assert run(["--add", "東京"], fake)[0] == 0
    code, out, _ = run(["--add", "台北"], fake)
    assert "已經在常用城市中" in out

    saved = json.loads((isolated_home / "favorites.json").read_text(encoding="utf-8"))
    assert [c["name"] for c in saved["cities"]] == ["臺北市", "東京"]

    code, out, _ = run(["--list"], fake)
    assert "1. 臺北市" in out and "2. 東京" in out

    fake.calls.clear()
    code, out, _ = run([], fake)
    assert code == 0
    assert "臺北市" in out and "東京" in out
    # 常用城市已存座標，不需要再查地名
    assert set(fake.hosts()) == {"api.open-meteo.com"}


def test_remove_by_name_and_index(fake):
    run(["--add", "台北"], fake)
    run(["--add", "東京"], fake)
    code, out, _ = run(["--remove", "臺北市"], fake)
    assert code == 0 and "已移除" in out
    code, out, _ = run(["--remove", "1"], fake)
    assert code == 0 and "東京" in out
    code, _, err = run(["--remove", "東京"], fake)
    assert code == 1 and "沒有" in err


def test_repeated_query_uses_cache(fake):
    run(["台北"], fake)
    run(["台北"], fake)
    assert len(fake.calls) == 2  # 一次地名 + 一次預報，第二次全走快取


def test_no_cache_flag(fake):
    run(["台北"], fake)
    run(["--no-cache", "台北"], fake)
    assert len(fake.calls) == 4


def test_clear_cache(fake):
    run(["台北"], fake)
    run(["--clear-cache"], fake)
    run(["台北"], fake)
    assert len(fake.calls) == 4


def test_corrupt_files_are_tolerated(fake, isolated_home):
    isolated_home.mkdir(parents=True)
    (isolated_home / "favorites.json").write_text("{not json", encoding="utf-8")
    (isolated_home / "cache").mkdir()
    (isolated_home / "cache" / "http_cache.json").write_text("garbage", encoding="utf-8")
    code, out, _ = run([], fake)
    assert code == 0
    code, out, _ = run(["台北"], fake)
    assert code == 0 and "臺北市" in out


def test_render_handles_missing_values():
    data = make_forecast()
    data["current"]["temperature_2m"] = None
    data["daily"]["precipitation_probability_max"] = [None] * 4
    text = render(Location("X", 0, 0), data)
    assert "氣溫 —" in text
    assert "降雨機率 —" in text


def test_describe_unknown_code():
    assert describe(0) == "晴朗"
    assert "未知" in describe(42)
    assert "未知" in describe(None)

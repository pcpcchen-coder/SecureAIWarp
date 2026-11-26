"""把 Open-Meteo 的回應轉成給人看的文字。"""

from __future__ import annotations

import datetime as dt
from typing import Any, List

from .api import Location

# WMO 天氣代碼（Open-Meteo 文件中的 weather_code）
WMO_CODES = {
    0: "晴朗",
    1: "大致晴朗",
    2: "局部多雲",
    3: "陰天",
    45: "有霧",
    48: "霧淞",
    51: "毛毛雨（小）",
    53: "毛毛雨（中）",
    55: "毛毛雨（大）",
    56: "凍毛毛雨（小）",
    57: "凍毛毛雨（大）",
    61: "小雨",
    63: "中雨",
    65: "大雨",
    66: "凍雨（小）",
    67: "凍雨（大）",
    71: "小雪",
    73: "中雪",
    75: "大雪",
    77: "雪粒",
    80: "陣雨（小）",
    81: "陣雨（中）",
    82: "陣雨（強）",
    85: "陣雪（小）",
    86: "陣雪（大）",
    95: "雷雨",
    96: "雷雨伴有小冰雹",
    99: "雷雨伴有大冰雹",
}

WEEKDAYS = ["一", "二", "三", "四", "五", "六", "日"]


def describe(code: Any) -> str:
    try:
        return WMO_CODES.get(int(code), f"未知天氣（代碼 {code}）")
    except (TypeError, ValueError):
        return "未知天氣"


def _num(v: Any, unit: str, digits: int = 0) -> str:
    if v is None:
        return "—"
    return f"{v:.{digits}f}{unit}"


def _day_label(date_str: str) -> str:
    try:
        d = dt.date.fromisoformat(date_str)
    except ValueError:
        return date_str
    return f"{d.month:02d}/{d.day:02d}（{WEEKDAYS[d.weekday()]}）"


def _at(seq: Any, i: int) -> Any:
    try:
        return seq[i]
    except (IndexError, TypeError, KeyError):
        return None


def render(loc: Location, data: dict, days: int = 3) -> str:
    cur = data.get("current", {}) or {}
    daily = data.get("daily", {}) or {}
    units = data.get("current_units", {}) or {}
    t_unit = units.get("temperature_2m", "°C")
    w_unit = units.get("wind_speed_10m", "km/h")
    p_unit = units.get("precipitation", "mm")

    lines: List[str] = []
    lines.append(f"== {loc.label} ==")
    time_str = str(cur.get("time", "")).replace("T", " ")
    lines.append(f"現在（{time_str}）：{describe(cur.get('weather_code'))}")
    lines.append(
        f"  氣溫 {_num(cur.get('temperature_2m'), t_unit, 1)}"
        f"（體感 {_num(cur.get('apparent_temperature'), t_unit, 1)}）"
        f"  濕度 {_num(cur.get('relative_humidity_2m'), '%')}"
        f"  風速 {_num(cur.get('wind_speed_10m'), ' ' + w_unit, 1)}"
        f"  降水 {_num(cur.get('precipitation'), ' ' + p_unit, 1)}"
    )

    dates = daily.get("time", []) or []
    lines.append(f"未來 {days} 天：")
    shown = 0
    # 第 0 筆是今天，從第 1 筆開始才是「未來」
    for i in range(1, len(dates)):
        if shown >= days:
            break
        tmax = _at(daily.get("temperature_2m_max"), i)
        tmin = _at(daily.get("temperature_2m_min"), i)
        pop = _at(daily.get("precipitation_probability_max"), i)
        lines.append(
            f"  {_day_label(dates[i])}  {describe(_at(daily.get('weather_code'), i)):<8}"
            f"  {_num(tmin, '')}~{_num(tmax, t_unit)}"
            f"  降雨機率 {_num(pop, '%')}"
        )
        shown += 1
    if shown == 0:
        lines.append("  （沒有預報資料）")
    return "\n".join(lines)

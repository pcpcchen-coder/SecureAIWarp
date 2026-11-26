"""命令列入口：weather [城市] / weather --add 城市 / weather --list ..."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__, paths
from .api import OpenMeteoClient, WeatherError, http_get_json
from .cache import FileCache
from .favorites import Favorites
from .format import render


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="weather",
        description="查詢現在天氣與未來三天預報（資料來源：Open-Meteo）。"
                    "不帶城市時顯示所有常用城市。",
    )
    p.add_argument("city", nargs="*", help="城市名稱，例如：台北、Tokyo、New York")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-a", "--add", metavar="城市", help="把城市加入常用清單")
    g.add_argument("-r", "--remove", metavar="城市或編號", help="從常用清單移除城市")
    g.add_argument("-l", "--list", action="store_true", help="列出常用城市（不查天氣）")
    g.add_argument("--clear-cache", action="store_true", help="清除快取")
    p.add_argument("--no-cache", action="store_true", help="略過快取，強制重新查詢 API")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[List[str]] = None, fetch=http_get_json, out=None, err=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    args = build_parser().parse_args(argv)

    cache = FileCache(paths.cache_file())
    favs = Favorites(paths.favorites_file())
    client = OpenMeteoClient(cache=cache, fetch=fetch, use_cache=not args.no_cache)

    def say(msg: str = "") -> None:
        print(msg, file=out)

    try:
        if args.clear_cache:
            cache.clear()
            say("已清除快取。")
            return 0

        if args.list:
            cities = favs.load()
            if not cities:
                say("目前沒有常用城市。用 `weather --add 台北` 加入。")
            for i, c in enumerate(cities, 1):
                say(f"{i}. {c.label}  ({c.latitude:.2f}, {c.longitude:.2f})")
            return 0

        if args.add:
            loc = client.geocode(args.add)
            if favs.add(loc):
                say(f"已加入常用城市：{loc.label}")
            else:
                say(f"「{loc.label}」已經在常用城市中。")
            return 0

        if args.remove:
            removed = favs.remove(args.remove)
            if not removed:
                print(f"常用城市中沒有「{args.remove}」。", file=err)
                return 1
            for c in removed:
                say(f"已移除：{c.label}")
            return 0

        if args.city:
            loc = client.geocode(" ".join(args.city))
            say(render(loc, client.forecast(loc)))
            return 0

        cities = favs.load()
        if not cities:
            say("還沒有常用城市。")
            say("  查詢：weather 台北")
            say("  加入常用：weather --add 台北")
            return 0
        status = 0
        for i, loc in enumerate(cities):
            if i:
                say()
            try:
                say(render(loc, client.forecast(loc)))
            except WeatherError as e:
                print(f"{loc.label}：{e}", file=err)
                status = 1
        return status
    except WeatherError as e:
        print(f"錯誤：{e}", file=err)
        return 1


if __name__ == "__main__":
    sys.exit(main())

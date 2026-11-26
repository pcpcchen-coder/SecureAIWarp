"""決定常用城市與快取檔案要放在哪裡。

優先順序：
1. 環境變數 WEATHER_HOME（兩者都放在這個目錄底下）
2. XDG_CONFIG_HOME / XDG_CACHE_HOME
3. ~/.config/weather-cli 與 ~/.cache/weather-cli
"""

from __future__ import annotations

import os
from pathlib import Path

APP = "weather-cli"


def config_dir() -> Path:
    home = os.environ.get("WEATHER_HOME")
    if home:
        return Path(home)
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP


def cache_dir() -> Path:
    home = os.environ.get("WEATHER_HOME")
    if home:
        return Path(home) / "cache"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / APP


def favorites_file() -> Path:
    return config_dir() / "favorites.json"


def cache_file() -> Path:
    return cache_dir() / "http_cache.json"

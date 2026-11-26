"""常用城市：存成 JSON，包含已查好的座標，下次不必再查地名。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .api import Location


class Favorites:
    def __init__(self, path: Path):
        self.path = Path(path)

    def load(self) -> List[Location]:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return []
        except (json.JSONDecodeError, OSError):
            return []
        items = data.get("cities", []) if isinstance(data, dict) else []
        out = []
        for d in items:
            try:
                out.append(Location.from_dict(d))
            except (KeyError, TypeError, ValueError):
                continue
        return out

    def _save(self, cities: List[Location]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"cities": [c.to_dict() for c in cities]}, f,
                      ensure_ascii=False, indent=2)

    @staticmethod
    def _same(a: Location, b: Location) -> bool:
        return round(a.latitude, 2) == round(b.latitude, 2) and \
            round(a.longitude, 2) == round(b.longitude, 2)

    def add(self, loc: Location) -> bool:
        """加入常用城市；已存在時回傳 False。"""
        cities = self.load()
        if any(self._same(c, loc) for c in cities):
            return False
        cities.append(loc)
        self._save(cities)
        return True

    def remove(self, query: str) -> List[Location]:
        """依名稱（不分大小寫）或清單編號（從 1 開始）移除，回傳被移除的城市。"""
        cities = self.load()
        q = query.strip()
        removed: List[Location] = []
        if q.isdigit():
            idx = int(q) - 1
            if 0 <= idx < len(cities):
                removed = [cities.pop(idx)]
        else:
            keep = []
            for c in cities:
                if c.name.casefold() == q.casefold():
                    removed.append(c)
                else:
                    keep.append(c)
            cities = keep
        if removed:
            self._save(cities)
        return removed

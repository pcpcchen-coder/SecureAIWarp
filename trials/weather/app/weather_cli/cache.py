"""簡單的檔案型 TTL 快取：同一個網址在有效期限內直接回傳上次的結果，不重打 API。"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Optional


class FileCache:
    def __init__(self, path: Path, clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self.clock = clock

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            # 快取壞掉或不存在就當作沒有快取
            return {}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def get(self, key: str, ttl: float) -> Optional[Any]:
        entry = self._load().get(key)
        if not isinstance(entry, dict) or "t" not in entry:
            return None
        if self.clock() - entry["t"] > ttl:
            return None
        return entry.get("v")

    def set(self, key: str, value: Any, max_age: float = 7 * 86400) -> None:
        now = self.clock()
        data = self._load()
        # 順便清掉太舊的項目，避免檔案越長越大
        data = {k: v for k, v in data.items()
                if isinstance(v, dict) and now - v.get("t", 0) <= max_age}
        data[key] = {"t": now, "v": value}
        self._save(data)

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

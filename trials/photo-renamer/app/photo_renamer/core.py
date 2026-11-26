"""Core logic: read capture time, plan renames, apply them, undo them."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

PHOTO_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp",
    ".heic", ".heif", ".dng", ".cr2", ".nef", ".arw", ".gif", ".bmp",
}
JOURNAL_NAME = ".photo-renamer-journal.json"
NAME_FORMAT = "%Y-%m-%d_%H%M%S"

# EXIF tag ids
_EXIF_IFD = 0x8769
_DATETIME_ORIGINAL = 0x9003
_DATETIME_DIGITIZED = 0x9004
_DATETIME = 0x0132


class PhotoRenamerError(Exception):
    pass


@dataclass
class PlannedRename:
    source: Path
    target: Path
    taken_at: datetime
    time_source: str  # "exif" or "mtime"

    @property
    def changes(self) -> bool:
        return self.source.name != self.target.name


def _parse_exif_datetime(value) -> datetime | None:
    if isinstance(value, bytes):
        value = value.decode("ascii", "ignore")
    if not isinstance(value, str):
        return None
    value = value.strip().strip("\x00")
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y:%m:%d %H:%M"):
        try:
            dt = datetime.strptime(value[:19], fmt)
        except ValueError:
            continue
        if dt.year < 1900:
            return None
        return dt
    return None


def read_exif_datetime(path: Path) -> datetime | None:
    """Return the EXIF capture time of an image, or None if unavailable."""
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover - Pillow is a declared dependency
        return None
    try:
        with Image.open(path) as img:
            exif = img.getexif()
            if not exif:
                return None
            sub = exif.get_ifd(_EXIF_IFD)
            for tag in (_DATETIME_ORIGINAL, _DATETIME_DIGITIZED):
                dt = _parse_exif_datetime(sub.get(tag))
                if dt:
                    return dt
            return _parse_exif_datetime(exif.get(_DATETIME))
    except Exception:
        return None


def get_capture_time(path: Path) -> tuple[datetime, str]:
    dt = read_exif_datetime(path)
    if dt is not None:
        return dt, "exif"
    return datetime.fromtimestamp(path.stat().st_mtime).replace(microsecond=0), "mtime"


def list_photos(folder: Path) -> list[Path]:
    return sorted(
        p for p in folder.iterdir()
        if p.is_file() and not p.name.startswith(".")
        and p.suffix.lower() in PHOTO_EXTENSIONS
    )


def _normalise_ext(path: Path) -> str:
    ext = path.suffix.lower()
    return ".jpg" if ext == ".jpeg" else ext


def plan_renames(folder: Path) -> list[PlannedRename]:
    """Work out the new name for every photo in ``folder`` without touching disk."""
    folder = Path(folder)
    if not folder.is_dir():
        raise PhotoRenamerError(f"不是資料夾: {folder}")

    photos = list_photos(folder)
    photo_names = {p.name.lower() for p in photos}
    # Names held by files we will not move (non-photos, hidden files...).
    occupied = {p.name.lower() for p in folder.iterdir() if p.name.lower() not in photo_names}

    infos = []
    for p in photos:
        dt, src = get_capture_time(p)
        base = dt.strftime(NAME_FORMAT)
        ext = _normalise_ext(p)
        # Files already carrying their exact base name get first claim on it,
        # so re-running the tool is a no-op.
        already = p.name.lower() == (base + ext).lower()
        infos.append((not already, dt, p.name, p, base, ext, src))
    infos.sort(key=lambda t: t[:3])

    assigned: set[str] = set()
    plan = []
    for _, dt, _, p, base, ext, src in infos:
        n = 0
        while True:
            name = f"{base}{ext}" if n == 0 else f"{base}_{n}{ext}"
            if name.lower() not in occupied and name.lower() not in assigned:
                break
            n += 1
        assigned.add(name.lower())
        plan.append(PlannedRename(p, folder / name, dt, src))
    plan.sort(key=lambda r: r.source.name)
    return plan


def _two_phase_move(folder: Path, moves: list[tuple[str, str]]) -> None:
    """Rename via temporary names so swaps/chains never overwrite anything."""
    token = uuid.uuid4().hex[:8]
    temps = []
    for i, (src, dst) in enumerate(moves):
        tmp = f".photo-renamer-tmp-{token}-{i}"
        os.rename(folder / src, folder / tmp)
        temps.append((tmp, dst))
    for tmp, dst in temps:
        if (folder / dst).exists():
            raise PhotoRenamerError(f"目標已存在，停止以免覆蓋: {dst} (暫存檔: {tmp})")
        os.rename(folder / tmp, folder / dst)


def _load_journal(folder: Path) -> list:
    path = folder / JOURNAL_NAME
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f).get("runs", [])


def _save_journal(folder: Path, runs: list) -> None:
    path = folder / JOURNAL_NAME
    if not runs:
        if path.exists():
            path.unlink()
        return
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"version": 1, "runs": runs}, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def apply_renames(folder: Path, plan: list[PlannedRename]) -> int:
    folder = Path(folder)
    moves = [(r.source.name, r.target.name) for r in plan if r.changes]
    if not moves:
        return 0
    runs = _load_journal(folder)
    runs.append({
        "time": datetime.now().isoformat(timespec="seconds"),
        "renames": [{"from": s, "to": d} for s, d in moves],
    })
    _save_journal(folder, runs)  # record before moving
    _two_phase_move(folder, moves)
    return len(moves)


def undo_last(folder: Path) -> int:
    """Revert the most recent rename run in ``folder``. Returns files restored."""
    folder = Path(folder)
    runs = _load_journal(folder)
    if not runs:
        raise PhotoRenamerError("沒有可以復原的紀錄")
    run = runs[-1]
    moves = []
    for item in run["renames"]:
        cur, orig = item["to"], item["from"]
        if not (folder / cur).exists():
            raise PhotoRenamerError(f"找不到檔案 {cur}，無法復原（是否已被移動或刪除？）")
        moves.append((cur, orig))
    current = {c.lower() for c, _ in moves}
    for _, orig in moves:
        if (folder / orig).exists() and orig.lower() not in current:
            raise PhotoRenamerError(f"原檔名 {orig} 已被其他檔案使用，無法復原")
    _two_phase_move(folder, moves)
    _save_journal(folder, runs[:-1])
    return len(moves)

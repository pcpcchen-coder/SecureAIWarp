import os
from datetime import datetime
from pathlib import Path

import pytest
from PIL import Image

from photo_renamer.cli import main
from photo_renamer.core import (
    JOURNAL_NAME,
    PhotoRenamerError,
    apply_renames,
    get_capture_time,
    plan_renames,
    undo_last,
)


def make_jpeg(path: Path, taken: str | None = None, mtime: datetime | None = None, color="red"):
    img = Image.new("RGB", (8, 8), color)
    if taken:
        exif = Image.Exif()
        exif.get_ifd(0x8769)[0x9003] = taken  # DateTimeOriginal
        img.save(path, "JPEG", exif=exif)
    else:
        img.save(path, "JPEG")
    if mtime:
        ts = mtime.timestamp()
        os.utime(path, (ts, ts))
    return path


def names(folder: Path):
    return sorted(p.name for p in folder.iterdir())


def contents(folder: Path):
    return {p.name: p.read_bytes() for p in folder.iterdir() if not p.name.startswith(".")}


def test_reads_exif_capture_time(tmp_path):
    p = make_jpeg(tmp_path / "IMG_0001.JPG", "2024:03:15 14:23:01")
    assert get_capture_time(p) == (datetime(2024, 3, 15, 14, 23, 1), "exif")


def test_falls_back_to_mtime(tmp_path):
    p = make_jpeg(tmp_path / "no_exif.jpg", mtime=datetime(2023, 1, 2, 3, 4, 5))
    assert get_capture_time(p) == (datetime(2023, 1, 2, 3, 4, 5), "mtime")


def test_invalid_exif_falls_back_to_mtime(tmp_path):
    p = make_jpeg(tmp_path / "bad.jpg", "0000:00:00 00:00:00", mtime=datetime(2022, 5, 6, 7, 8, 9))
    assert get_capture_time(p) == (datetime(2022, 5, 6, 7, 8, 9), "mtime")


def test_unreadable_image_falls_back_to_mtime(tmp_path):
    p = tmp_path / "broken.jpg"
    p.write_bytes(b"not really a jpeg")
    ts = datetime(2021, 1, 1, 0, 0, 0).timestamp()
    os.utime(p, (ts, ts))
    assert get_capture_time(p)[1] == "mtime"


def test_preview_does_not_touch_files(tmp_path, capsys):
    make_jpeg(tmp_path / "DSC_9.JPG", "2024:03:15 14:23:01")
    before = names(tmp_path)
    assert main(["preview", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "DSC_9.JPG  ->  2024-03-15_142301.jpg" in out
    assert names(tmp_path) == before


def test_rename_and_extension_normalised(tmp_path):
    make_jpeg(tmp_path / "IMG_1.JPEG", "2024:03:15 14:23:01")
    plan = plan_renames(tmp_path)
    assert apply_renames(tmp_path, plan) == 1
    assert "2024-03-15_142301.jpg" in names(tmp_path)
    assert "IMG_1.JPEG" not in names(tmp_path)


def test_same_timestamp_gets_suffix_without_overwrite(tmp_path):
    make_jpeg(tmp_path / "a.jpg", "2024:03:15 14:23:01", color="red")
    make_jpeg(tmp_path / "b.jpg", "2024:03:15 14:23:01", color="blue")
    make_jpeg(tmp_path / "c.jpg", "2024:03:15 14:23:01", color="green")
    data_before = sorted(contents(tmp_path).values())
    apply_renames(tmp_path, plan_renames(tmp_path))
    assert set(contents(tmp_path)) == {
        "2024-03-15_142301.jpg", "2024-03-15_142301_1.jpg", "2024-03-15_142301_2.jpg"}
    assert sorted(contents(tmp_path).values()) == data_before


def test_already_named_file_keeps_name_and_newcomer_gets_suffix(tmp_path):
    make_jpeg(tmp_path / "2024-03-15_142301.jpg", "2024:03:15 14:23:01", color="red")
    make_jpeg(tmp_path / "AAA.jpg", "2024:03:15 14:23:01", color="blue")
    kept = (tmp_path / "2024-03-15_142301.jpg").read_bytes()
    plan = {r.source.name: r.target.name for r in plan_renames(tmp_path)}
    assert plan == {"2024-03-15_142301.jpg": "2024-03-15_142301.jpg",
                    "AAA.jpg": "2024-03-15_142301_1.jpg"}
    apply_renames(tmp_path, plan_renames(tmp_path))
    assert (tmp_path / "2024-03-15_142301.jpg").read_bytes() == kept
    assert len(contents(tmp_path)) == 2


def test_case_insensitive_collision_avoided(tmp_path):
    # Same name differing only by case must still be treated as a clash
    # (macOS/Windows file systems are case-insensitive).
    make_jpeg(tmp_path / "a.jpg", "2024:03:15 14:23:01", color="red")
    make_jpeg(tmp_path / "b.JPG", "2024:03:15 14:23:01", color="blue")
    targets = sorted(r.target.name.lower() for r in plan_renames(tmp_path))
    assert targets == ["2024-03-15_142301.jpg", "2024-03-15_142301_1.jpg"]


def test_name_swap_is_safe(tmp_path):
    # a.jpg should become b's name and vice versa; two-phase move must not lose data.
    make_jpeg(tmp_path / "2024-01-01_000000.jpg", "2025:01:01 00:00:00", color="red")
    make_jpeg(tmp_path / "2025-01-01_000000.jpg", "2024:01:01 00:00:00", color="blue")
    red = (tmp_path / "2024-01-01_000000.jpg").read_bytes()
    apply_renames(tmp_path, plan_renames(tmp_path))
    assert (tmp_path / "2025-01-01_000000.jpg").read_bytes() == red
    assert len(contents(tmp_path)) == 2


def test_rerun_is_noop(tmp_path):
    make_jpeg(tmp_path / "x.jpg", "2024:03:15 14:23:01")
    make_jpeg(tmp_path / "y.jpg", "2024:03:15 14:23:01", color="blue")
    apply_renames(tmp_path, plan_renames(tmp_path))
    after = names(tmp_path)
    plan = plan_renames(tmp_path)
    assert not any(r.changes for r in plan)
    assert apply_renames(tmp_path, plan) == 0
    assert names(tmp_path) == after


def test_ignores_non_photos(tmp_path):
    (tmp_path / "notes.txt").write_text("hi")
    make_jpeg(tmp_path / "p.jpg", "2024:03:15 14:23:01")
    apply_renames(tmp_path, plan_renames(tmp_path))
    assert "notes.txt" in names(tmp_path)


def test_undo_restores_original_names(tmp_path):
    make_jpeg(tmp_path / "IMG_A.jpg", "2024:03:15 14:23:01", color="red")
    make_jpeg(tmp_path / "IMG_B.jpg", "2024:03:15 14:23:01", color="blue")
    make_jpeg(tmp_path / "IMG_C.png.jpg", mtime=datetime(2020, 2, 2, 2, 2, 2))
    before = contents(tmp_path)
    apply_renames(tmp_path, plan_renames(tmp_path))
    assert contents(tmp_path) != before
    assert undo_last(tmp_path) == 3
    assert contents(tmp_path) == before
    assert not (tmp_path / JOURNAL_NAME).exists()


def test_undo_multiple_runs_in_order(tmp_path):
    make_jpeg(tmp_path / "first.jpg", "2024:03:15 14:23:01")
    original = names(tmp_path)
    apply_renames(tmp_path, plan_renames(tmp_path))
    make_jpeg(tmp_path / "second.jpg", "2024:03:16 10:00:00")
    apply_renames(tmp_path, plan_renames(tmp_path))
    undo_last(tmp_path)
    assert "second.jpg" in names(tmp_path)
    assert "2024-03-15_142301.jpg" in names(tmp_path)
    undo_last(tmp_path)
    assert "first.jpg" in names(tmp_path)
    assert sorted(set(names(tmp_path)) - {"second.jpg"}) == original


def test_undo_without_journal_errors(tmp_path):
    with pytest.raises(PhotoRenamerError):
        undo_last(tmp_path)


def test_undo_refuses_to_overwrite(tmp_path):
    make_jpeg(tmp_path / "orig.jpg", "2024:03:15 14:23:01")
    apply_renames(tmp_path, plan_renames(tmp_path))
    (tmp_path / "orig.jpg").write_text("someone else")
    with pytest.raises(PhotoRenamerError):
        undo_last(tmp_path)
    assert (tmp_path / "orig.jpg").read_text() == "someone else"


def test_cli_rename_requires_confirmation(tmp_path, monkeypatch):
    make_jpeg(tmp_path / "z.jpg", "2024:03:15 14:23:01")
    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert main(["rename", str(tmp_path)]) == 1
    assert names(tmp_path) == ["z.jpg"]


def test_cli_rename_yes_then_undo(tmp_path, capsys):
    make_jpeg(tmp_path / "z.jpg", "2024:03:15 14:23:01")
    assert main(["rename", "--yes", str(tmp_path)]) == 0
    assert "2024-03-15_142301.jpg" in names(tmp_path)
    assert main(["undo", str(tmp_path)]) == 0
    assert names(tmp_path) == ["z.jpg"]


def test_cli_bad_folder(tmp_path, capsys):
    assert main(["preview", str(tmp_path / "missing")]) == 2
    assert "錯誤" in capsys.readouterr().err

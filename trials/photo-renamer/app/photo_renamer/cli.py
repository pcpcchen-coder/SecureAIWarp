"""Command-line interface for photo-renamer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core import PhotoRenamerError, apply_renames, plan_renames, undo_last


def _print_plan(plan) -> int:
    changes = [r for r in plan if r.changes]
    for r in plan:
        tag = "EXIF" if r.time_source == "exif" else "修改時間"
        if r.changes:
            print(f"  {r.source.name}  ->  {r.target.name}   [{tag}]")
        else:
            print(f"  {r.source.name}  (不變)")
    print(f"共 {len(plan)} 張照片，{len(changes)} 張會改名。")
    return len(changes)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="photo-renamer",
        description="依拍攝時間重新命名資料夾內的照片（例如 2024-03-15_142301.jpg）。",
    )
    sub = p.add_subparsers(dest="command", required=True)
    pv = sub.add_parser("preview", help="只顯示會怎麼改名，不動任何檔案")
    pv.add_argument("folder", type=Path)
    rn = sub.add_parser("rename", help="實際改名（會先顯示預覽並詢問確認）")
    rn.add_argument("folder", type=Path)
    rn.add_argument("-y", "--yes", action="store_true", help="不詢問，直接執行")
    ud = sub.add_parser("undo", help="復原上一次的改名")
    ud.add_argument("folder", type=Path)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "preview":
            _print_plan(plan_renames(args.folder))
            print("（這只是預覽，沒有更動任何檔案。用 rename 指令實際執行。）")
        elif args.command == "rename":
            plan = plan_renames(args.folder)
            if _print_plan(plan) == 0:
                print("沒有需要改名的檔案。")
                return 0
            if not args.yes:
                ans = input("確定要改名嗎？[y/N] ").strip().lower()
                if ans not in ("y", "yes"):
                    print("已取消。")
                    return 1
            n = apply_renames(args.folder, plan)
            print(f"已改名 {n} 個檔案。要復原請執行: photo-renamer undo {args.folder}")
        elif args.command == "undo":
            n = undo_last(args.folder)
            print(f"已復原 {n} 個檔案。")
    except PhotoRenamerError as e:
        print(f"錯誤: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

# photo-renamer

把資料夾裡的照片依「拍攝時間」重新命名，例如 `IMG_4821.JPG` → `2024-03-15_142301.jpg`。

- 拍攝時間取自 EXIF（DateTimeOriginal → DateTimeDigitized → DateTime）；讀不到就用檔案修改時間。
- 同一秒的照片會自動加上 `_1`、`_2`…，絕不互相覆蓋（大小寫不同的檔名也視為相同）。
- 可以先 `preview` 預覽，確認後再 `rename`。
- 每次改名都會寫入資料夾內的 `.photo-renamer-journal.json`，可以用 `undo` 復原（可連續復原多次，從最近一次往回）。
- 已經是正確名稱的照片不會被動到，重複執行是安全的。
- 副檔名轉成小寫，`.jpeg` 統一成 `.jpg`。只處理照片副檔名（jpg/jpeg/png/tif/tiff/webp/heic/heif/dng/cr2/nef/arw/gif/bmp），其他檔案與隱藏檔不動；只處理該資料夾本層，不進子資料夾。

## 安裝

需要 Python 3.9 以上。所有套件都裝在這個目錄的虛擬環境 `.venv` 內：

```bash
cd photo-renamer
python3 -m venv .venv
.venv/bin/pip install -e ".[test]"     # 安裝本工具 + Pillow + pytest
```

## 使用

```bash
# 1. 預覽（不會改任何檔案）
.venv/bin/photo-renamer preview ~/Pictures/手機匯出

# 2. 實際改名（會先列出預覽並詢問 y/N；加 -y 可跳過詢問）
.venv/bin/photo-renamer rename ~/Pictures/手機匯出
.venv/bin/photo-renamer rename -y ~/Pictures/手機匯出

# 3. 改錯了？復原上一次的改名
.venv/bin/photo-renamer undo ~/Pictures/手機匯出
```

也可以用 `.venv/bin/python -m photo_renamer ...` 執行，或先 `source .venv/bin/activate` 後直接打 `photo-renamer`。

預覽輸出範例：

```
  DSC_0001.JPG  ->  2024-03-15_142301.jpg   [EXIF]
  DSC_0002.JPG  ->  2024-03-15_142301_1.jpg   [EXIF]
  screenshot.png  ->  2024-05-01_090000.png   [修改時間]
共 3 張照片，3 張會改名。
```

結束代碼：`0` 成功、`1` 使用者取消、`2` 錯誤（例如資料夾不存在、沒有可復原的紀錄）。

## 注意事項

- HEIC/RAW 等格式 Pillow 不一定讀得到 EXIF，這時會改用檔案修改時間（預覽中標示為 `[修改時間]`）。複製檔案時若修改時間被改掉，名稱就會不準，請先預覽確認。
- 復原依賴 `.photo-renamer-journal.json`，請勿刪除；若改名後檔案又被移動、刪除，或原檔名已被其他檔案佔用，`undo` 會拒絕執行而不會覆蓋任何東西。
- 改名採兩階段（先改成暫存名再改成最終名），因此即使新舊名稱互換也不會遺失檔案。

## 測試

```bash
.venv/bin/python -m pytest -v
```

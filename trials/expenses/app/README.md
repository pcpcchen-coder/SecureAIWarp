# 旅行記帳（本機網頁）

在自己電腦上跑的記帳網頁：新增花費（金額、幣別、類別、備註、日期）、列表、依月份／類別統計、全部換算成台幣、匯出 CSV。資料存在本機 SQLite，關掉重開還在。

## 安裝

需要 Python 3.10 以上。所有套件都裝在本目錄的 `.venv` 裡，不會動到系統。

```bash
cd apps/expenses
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt        # 執行用（Flask）
.venv/bin/pip install -r requirements-dev.txt    # 要跑測試才需要（pytest）
```

Windows 請把 `.venv/bin/` 換成 `.venv\Scripts\`。

## 設定匯率 API 金鑰

匯率來自 [exchangerate-api.com](https://www.exchangerate-api.com/) 的 v6 API。到官網註冊後會拿到一組金鑰。提供方式擇一：

1. **環境變數**（優先）：
   ```bash
   export EXCHANGERATE_API_KEY=你的金鑰
   ```
2. **`.env` 檔**：把 `.env.example` 複製成 `.env`，填入
   ```
   EXCHANGERATE_API_KEY=你的金鑰
   ```
   `.env` 已列在 `.gitignore`，請不要分享或提交它。

沒設定金鑰也能用：台幣花費照常；外幣花費會先存下來標示「未換算」，之後有金鑰、有網路時按頁面上的「重新換算」即可。

## 啟動

```bash
.venv/bin/python run.py              # 會自動開瀏覽器到 http://127.0.0.1:5000/
.venv/bin/python run.py --port 8080 --no-browser
```

伺服器只綁定 `127.0.0.1`，同一個 Wi-Fi 的其他人連不到。按 Ctrl+C 結束。

## 資料與匯率

- 資料檔：`data/expenses.db`（可用環境變數 `EXPENSES_DB` 改位置）。備份就複製這個檔案。
- 程式只會連到 `https://v6.exchangerate-api.com/v6/<金鑰>/latest/TWD`，一次取得以台幣為基準的全部匯率，快取 6 小時；連不上時沿用上次的快取。
- 每筆花費**以新增當下的匯率**換成台幣並保存，之後匯率變動不會改到舊紀錄。
- 記錄台幣（TWD）時完全不連網。

## 匯出 CSV

頁面上的「匯出 CSV」會依目前的月份／類別篩選匯出。檔案為 UTF-8（含 BOM，Excel 可直接開啟中文），欄位：`id, date, amount, currency, category, note, twd_rate, twd_amount`。

## 測試

```bash
.venv/bin/python -m pytest -q
```

測試用假的 API 回應（照真實 v6 格式），並且會封鎖所有網路連線，不需要金鑰或網路。

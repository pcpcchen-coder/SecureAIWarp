# weather：命令列天氣工具

輸入城市名稱，顯示現在天氣與未來三天預報。資料來自 [Open-Meteo](https://open-meteo.com/)，免費而且不需要 API 金鑰。

```
$ weather 台北
== 臺北市, 臺灣 ==
現在（2026-11-26 14:00）：局部多雲
  氣溫 23.4°C（體感 24.1°C）  濕度 71%  風速 9.7 km/h  降水 0.0 mm
未來 3 天：
  11/27（五）  小雨        18~22°C  降雨機率 80%
  11/28（六）  陰天        18~21°C  降雨機率 35%
  11/29（日）  晴朗        19~25°C  降雨機率 5%
```
（上面的數字只是示意。）

## 安裝

需要 Python 3.9 以上。程式本身只用標準函式庫，測試要用到 pytest。所有套件都裝在本目錄的虛擬環境 `.venv` 裡，不會裝到系統。

```bash
cd apps/weather
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'     # 不跑測試的話，用 .venv/bin/pip install -e . 就可以
```

安裝好後，指令在 `.venv/bin/weather`。可以先 `source .venv/bin/activate`，之後直接打 `weather`。
不安裝也能執行：`python3 -m weather_cli 台北`（要在本目錄下執行）。

## 使用方式

| 指令 | 說明 |
|---|---|
| `weather 台北` | 查詢一個城市（英文也可以，例如 `weather Tokyo`、`weather New York`） |
| `weather --add 台北` / `-a` | 把城市加入常用清單 |
| `weather` | 不帶參數：列出所有常用城市的天氣 |
| `weather --list` / `-l` | 只列出常用城市，不查天氣 |
| `weather --remove 臺北市` / `-r` | 依名稱（以 `--list` 顯示的名稱為準）或編號移除，例如 `weather -r 1` |
| `weather --no-cache 台北` | 略過快取，強制重新查詢 |
| `weather --clear-cache` | 清除快取 |

查詢成功時結束代碼為 0；找不到城市、網路或 API 錯誤時會印出原因並以 1 結束。

### 中文城市名稱

Open-Meteo 的地名查詢對中文名稱（尤其是「台／臺」、省略「市」）不一定查得到，所以程式內建了常見城市的對照表（`weather_cli/aliases.py`），例如「台北」「臺北市」都會以 `Taipei` 查詢，顯示時仍是中文名稱。不在表中的城市會原樣送出；如果查不到，改用英文名稱通常就可以。也可以直接在表中補上自己常用的城市。

### 快取（不重複打 API）

- 天氣預報：同一地點 10 分鐘內重複查詢直接使用快取。
- 地名查詢：同一名稱 1 天內使用快取。
- 常用城市存了查好的座標，所以 `weather`（不帶參數）只會呼叫天氣預報 API，不會再查地名。
- 錯誤回應不會被快取。快取超過 7 天的項目會自動清掉。

### 資料存放位置

| 資料 | 預設位置 |
|---|---|
| 常用城市 | `~/.config/weather-cli/favorites.json`（或 `$XDG_CONFIG_HOME/weather-cli/`） |
| 快取 | `~/.cache/weather-cli/http_cache.json`（或 `$XDG_CACHE_HOME/weather-cli/`） |

設定環境變數 `WEATHER_HOME=/某個/目錄` 時，兩者都改放到那個目錄底下（快取在其中的 `cache/` 子目錄）。

## 會連到的網址

只會連到 Open-Meteo 的兩個服務（HTTPS GET）：

- 地名查詢：`https://geocoding-api.open-meteo.com/v1/search?name=…&count=1&language=zh&format=json`
- 天氣預報：`https://api.open-meteo.com/v1/forecast?latitude=…&longitude=…&current=…&daily=…&timezone=…&forecast_days=4`
  （`forecast_days=4` 是今天加上未來三天；畫面上的「未來 3 天」從明天開始。）

如果需要經過 proxy，Python 會自動使用 `HTTPS_PROXY` 環境變數。

## 測試

```bash
.venv/bin/python -m pytest -q
```

測試完全不連網路：HTTP 呼叫換成依照 Open-Meteo 真實回應格式做的假資料，`urllib.request.urlopen` 也被擋掉，萬一有程式碼誤連網路，測試會失敗。常用城市與快取檔案都寫在 pytest 的暫存目錄。

## 檔案結構

```
weather_cli/
  cli.py        命令列參數與流程
  api.py        Open-Meteo 用戶端（地名查詢、天氣預報、錯誤處理）
  aliases.py    中文城市名稱對照表
  cache.py      檔案型 TTL 快取
  favorites.py  常用城市
  format.py     輸出格式、WMO 天氣代碼轉中文
  paths.py      設定與快取檔案位置
tests/          pytest 測試
```

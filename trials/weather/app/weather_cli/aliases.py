"""常見中文城市名 → Open-Meteo 地名查詢較容易命中的英文名稱。

Open-Meteo 的地名查詢對中文（尤其是「台／臺」異體字、簡稱）命中率不穩定，
因此先把常見名稱轉成英文再查；回傳結果仍會用 language=zh 顯示中文名稱。
不在表中的名稱會原樣送出查詢。
"""

from __future__ import annotations

ALIASES = {
    # 台灣
    "台北": "Taipei", "新北": "New Taipei", "桃園": "Taoyuan", "台中": "Taichung",
    "台南": "Tainan", "高雄": "Kaohsiung", "基隆": "Keelung", "新竹": "Hsinchu",
    "嘉義": "Chiayi", "苗栗": "Miaoli", "彰化": "Changhua", "南投": "Nantou",
    "雲林": "Douliu", "屏東": "Pingtung", "宜蘭": "Yilan", "花蓮": "Hualien",
    "台東": "Taitung", "澎湖": "Magong", "馬公": "Magong", "金門": "Jincheng",
    "馬祖": "Nangan",
    # 其他常見城市
    "香港": "Hong Kong", "澳門": "Macau", "北京": "Beijing", "上海": "Shanghai",
    "廣州": "Guangzhou", "深圳": "Shenzhen", "東京": "Tokyo", "大阪": "Osaka",
    "京都": "Kyoto", "福岡": "Fukuoka", "札幌": "Sapporo", "沖繩": "Naha", "那霸": "Naha",
    "首爾": "Seoul", "釜山": "Busan", "新加坡": "Singapore", "曼谷": "Bangkok",
    "吉隆坡": "Kuala Lumpur", "河內": "Hanoi", "胡志明市": "Ho Chi Minh City",
    "馬尼拉": "Manila", "雪梨": "Sydney", "墨爾本": "Melbourne", "倫敦": "London",
    "巴黎": "Paris", "柏林": "Berlin", "紐約": "New York", "洛杉磯": "Los Angeles",
    "舊金山": "San Francisco", "西雅圖": "Seattle", "溫哥華": "Vancouver",
    "多倫多": "Toronto",
}


def resolve(name: str) -> str:
    """回傳要送去地名查詢的字串。"""
    n = name.strip().replace("臺", "台")
    if n in ALIASES:
        return ALIASES[n]
    for suffix in ("市", "縣"):
        if n.endswith(suffix) and n[:-1] in ALIASES:
            return ALIASES[n[:-1]]
    return name.strip()

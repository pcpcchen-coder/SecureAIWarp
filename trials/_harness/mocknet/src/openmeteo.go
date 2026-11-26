package main

import (
	"fmt"
	"hash/fnv"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---------------- geocoding-api.open-meteo.com ----------------

type place struct {
	ID          int
	Names       map[string]string // language -> name ("en" is the default)
	Aliases     []string          // extra search keys (any language)
	Lat, Lon    float64
	Elevation   float64
	FeatureCode string
	CC          string
	Admin       [][3]any // {level(1..4), id, map[lang]name}
	TZ          string
	Population  int
	Postcodes   []string
	CountryID   int
	Country     map[string]string
}

func L(en, zh string) map[string]string { return map[string]string{"en": en, "zh": zh} }

var places = []place{
	{ID: 1668341, Names: L("Taipei", "台北市"), Aliases: []string{"台北", "臺北", "台北市", "臺北市", "taipei city"},
		Lat: 25.05306, Lon: 121.52639, Elevation: 5, FeatureCode: "PPLC", CC: "TW",
		Admin: [][3]any{{1, 7280291, L("Taiwan", "臺灣省")}, {2, 1668338, L("Taipei City", "臺北市")}},
		TZ:    "Asia/Taipei", Population: 7871900, CountryID: 1668284, Country: L("Taiwan", "台湾")},
	{ID: 1980019, Names: L("Taipei Songshan Airport", "臺北松山機場"), Aliases: []string{"台北松山機場", "臺北松山機場", "松山機場"},
		Lat: 25.06405, Lon: 121.55022, Elevation: 5, FeatureCode: "AIRP", CC: "TW",
		Admin: [][3]any{{1, 7280291, L("Taiwan", "臺灣省")}, {2, 1668338, L("Taipei City", "臺北市")}, {3, 1668680, L("Songshan", "松山區")}, {4, 11701407, L("Jingzhong", "敬仲里")}},
		TZ:    "Asia/Taipei", CountryID: 1668284, Country: L("Taiwan", "台湾")},
	{ID: 1850147, Names: L("Tokyo", "東京"), Aliases: []string{"東京", "东京", "東京都", "とうきょう"},
		Lat: 35.6895, Lon: 139.69171, Elevation: 44, FeatureCode: "PPLC", CC: "JP",
		Admin: [][3]any{{1, 1850144, L("Tokyo", "东京都")}},
		TZ:    "Asia/Tokyo", Population: 9733276, CountryID: 1861060, Country: L("Japan", "日本")},
	{ID: 2643743, Names: L("London", "伦敦"), Aliases: []string{"倫敦", "伦敦"},
		Lat: 51.50853, Lon: -0.12574, Elevation: 25, FeatureCode: "PPLC", CC: "GB",
		Admin: [][3]any{{1, 6269131, L("England", "英格兰")}, {2, 2648110, L("Greater London", "大伦敦")}},
		TZ:    "Europe/London", Population: 8961989, CountryID: 2635167, Country: L("United Kingdom", "英国")},
	{ID: 6058560, Names: L("London", "伦敦"), Aliases: []string{"倫敦", "伦敦"},
		Lat: 42.98339, Lon: -81.23304, Elevation: 252, FeatureCode: "PPL", CC: "CA",
		Admin: [][3]any{{1, 6093943, L("Ontario", "安大略省")}, {2, 6073256, L("Middlesex County", "米德尔塞克斯县")}, {3, 13680305, L("London", "伦敦")}},
		TZ:    "America/Toronto", Population: 422324, CountryID: 6251999, Country: L("Canada", "加拿大")},
	{ID: 4517009, Names: L("London", "伦敦"), Aliases: []string{"倫敦", "伦敦"},
		Lat: 39.88645, Lon: -83.44825, Elevation: 321, FeatureCode: "PPLA2", CC: "US",
		Admin: [][3]any{{1, 5165418, L("Ohio", "俄亥俄州")}, {2, 4517365, L("Madison", "麦迪逊县")}, {3, 4517024, L("City of London", "伦敦市")}},
		TZ:    "America/New_York", Population: 10060, Postcodes: []string{"43140"}, CountryID: 6252001, Country: L("United States", "美国")},
}

func pick(m map[string]string, lang string) string {
	if v, ok := m[lang]; ok && v != "" {
		return v
	}
	return m["en"]
}

func omError(w http.ResponseWriter, reason string) {
	o := obj{}
	o.set("reason", reason)
	o.set("error", true)
	writeJSON(w, http.StatusBadRequest, o)
}

func geocoding(w http.ResponseWriter, r *http.Request, rec *logRec) {
	start := time.Now()
	if r.URL.Path != "/v1/search" && r.URL.Path != "/v1/get" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	if r.URL.Path == "/v1/get" {
		id, _ := strconv.Atoi(q.Get("id"))
		for _, p := range places {
			if p.ID == id {
				writeJSON(w, 200, placeJSON(p, langOf(q)))
				return
			}
		}
		omError(w, "Invalid id")
		return
	}
	if !q.Has("name") {
		omError(w, "No value found (expected type 'String') at path 'name'. No String was found at 'name'.")
		return
	}
	name := strings.ToLower(strings.TrimSpace(q.Get("name")))
	count := 10
	if c := q.Get("count"); c != "" {
		n, err := strconv.Atoi(c)
		if err != nil || n < 1 || n > 100 {
			omError(w, "Parameter count must be between 1 and 100.")
			return
		}
		count = n
	}
	lang := langOf(q)
	cc := strings.ToUpper(q.Get("countryCode"))
	var res []any
	if len([]rune(name)) >= 2 {
		for _, p := range places {
			if cc != "" && p.CC != cc {
				continue
			}
			keys := append([]string{}, p.Aliases...)
			for _, n := range p.Names {
				keys = append(keys, n)
			}
			hit := false
			for _, k := range keys {
				if strings.HasPrefix(strings.ToLower(k), name) {
					hit = true
					break
				}
			}
			if hit && len(res) < count {
				res = append(res, placeJSON(p, lang))
			}
		}
	}
	out := obj{}
	if len(res) > 0 {
		out.set("results", res)
	}
	out.set("generationtime_ms", num{float64(time.Since(start).Microseconds())/1000 + 0.07, 8})
	rec.Note = fmt.Sprintf("name=%q results=%d", q.Get("name"), len(res))
	if q.Get("format") == "protobuf" {
		rec.Note += " (protobuf requested; JSON returned)"
	}
	writeJSON(w, 200, out)
}

func langOf(q url.Values) string {
	l := strings.ToLower(q.Get("language"))
	if l == "" {
		return "en"
	}
	if strings.HasPrefix(l, "zh") {
		return "zh"
	}
	return l
}

func placeJSON(p place, lang string) obj {
	o := obj{}
	o.set("id", p.ID)
	o.set("name", pick(p.Names, lang))
	o.set("latitude", p.Lat)
	o.set("longitude", p.Lon)
	o.set("elevation", num{p.Elevation, 1})
	o.set("feature_code", p.FeatureCode)
	o.set("country_code", p.CC)
	for _, a := range p.Admin {
		o.set(fmt.Sprintf("admin%d_id", a[0]), a[1])
	}
	o.set("timezone", p.TZ)
	if p.Population > 0 {
		o.set("population", p.Population)
	}
	if len(p.Postcodes) > 0 {
		o.set("postcodes", p.Postcodes)
	}
	o.set("country_id", p.CountryID)
	o.set("country", pick(p.Country, lang))
	for _, a := range p.Admin {
		o.set(fmt.Sprintf("admin%d", a[0]), pick(a[2].(map[string]string), lang))
	}
	return o
}

// ---------------- api.open-meteo.com ----------------

type varSpec struct {
	unit string
	dec  int
	kind string // temp, wind, precip, snow, other, time
}

func specFor(name string) varSpec {
	n := strings.ToLower(name)
	switch {
	case n == "sunrise" || n == "sunset":
		return varSpec{"iso8601", 0, "time"}
	case strings.Contains(n, "temperature") || strings.HasPrefix(n, "dew_point") || strings.HasPrefix(n, "dewpoint") || n == "temperature":
		return varSpec{"°C", 1, "temp"}
	case strings.Contains(n, "humidity") || strings.Contains(n, "cloud") || strings.Contains(n, "probability"):
		return varSpec{"%", 0, "other"}
	case strings.Contains(n, "weather_code") || strings.Contains(n, "weathercode"):
		return varSpec{"wmo code", 0, "other"}
	case strings.Contains(n, "direction"):
		return varSpec{"°", 0, "other"}
	case strings.Contains(n, "wind") || strings.Contains(n, "gust"):
		return varSpec{"km/h", 1, "wind"}
	case strings.Contains(n, "snow"):
		return varSpec{"cm", 2, "snow"}
	case strings.Contains(n, "precipitation_hours"):
		return varSpec{"h", 1, "other"}
	case strings.Contains(n, "precipitation") || strings.Contains(n, "rain") || strings.Contains(n, "showers"):
		return varSpec{"mm", 2, "precip"}
	case strings.Contains(n, "pressure"):
		return varSpec{"hPa", 1, "other"}
	case n == "is_day":
		return varSpec{"", 0, "other"}
	case strings.HasPrefix(n, "uv_index"):
		return varSpec{"", 2, "other"}
	case n == "visibility":
		return varSpec{"m", 1, "other"}
	case strings.Contains(n, "duration"):
		return varSpec{"s", 2, "other"}
	case strings.Contains(n, "radiation_sum"):
		return varSpec{"MJ/m²", 2, "other"}
	case strings.Contains(n, "radiation") || strings.Contains(n, "irradiance"):
		return varSpec{"W/m²", 1, "other"}
	case strings.Contains(n, "evapotranspiration"):
		return varSpec{"mm", 2, "precip"}
	case strings.Contains(n, "soil_moisture"):
		return varSpec{"m³/m³", 3, "other"}
	case strings.Contains(n, "freezing_level") || strings.Contains(n, "height"):
		return varSpec{"m", 1, "other"}
	case strings.Contains(n, "cape"):
		return varSpec{"J/kg", 1, "other"}
	}
	return varSpec{"", 1, "other"}
}

func hash01(parts ...any) float64 {
	h := fnv.New64a()
	fmt.Fprint(h, parts...)
	return float64(h.Sum64()%1000000) / 1000000
}

type wx struct{ lat, lon float64 }

var wmoCodes = []int{0, 1, 2, 3, 3, 2, 1, 45, 51, 53, 61, 63, 80, 61, 95}

func (x wx) dayKey(t time.Time) string { return t.UTC().Format("2006-01-02") }

func (x wx) dayCode(t time.Time) int {
	return wmoCodes[int(hash01("code", x.dayKey(t), math.Round(x.lat), math.Round(x.lon))*float64(len(wmoCodes)))]
}

func (x wx) tempMean(t time.Time) float64 {
	alat := math.Abs(x.lat)
	doy := float64(t.UTC().YearDay())
	season := math.Cos(2 * math.Pi * (doy - 200) / 365)
	if x.lat < 0 {
		season = -season
	}
	return 31 - 0.35*alat + 0.2*alat*season + (hash01("tday", x.dayKey(t), math.Round(x.lat))-0.5)*3
}

// localHour returns solar local hour (0..24) at t.
func (x wx) solarHour(t time.Time) float64 {
	u := t.UTC()
	h := float64(u.Hour()) + float64(u.Minute())/60 + x.lon/15
	return math.Mod(h+48, 24)
}

func (x wx) temp(t time.Time) float64 {
	return x.tempMean(t) + 4*math.Cos(2*math.Pi*(x.solarHour(t)-14)/24)
}

// dayLength in hours from latitude and day of year.
func (x wx) dayLength(t time.Time) float64 {
	doy := float64(t.YearDay())
	decl := 23.44 * math.Pi / 180 * math.Sin(2*math.Pi*(284+doy)/365)
	lat := x.lat * math.Pi / 180
	c := -math.Tan(lat) * math.Tan(decl)
	c = math.Max(-1, math.Min(1, c))
	return 2 * math.Acos(c) * 180 / math.Pi / 15
}

func (x wx) sun(day time.Time, loc *time.Location) (time.Time, time.Time) {
	dl := x.dayLength(day)
	// Solar noon in UTC hours.
	noonUTC := 12 - x.lon/15
	y, m, d := day.Date()
	base := time.Date(y, m, d, 0, 0, 0, 0, loc)
	// Find the UTC date matching the local date's noon.
	mid := base.Add(12 * time.Hour).UTC()
	noon := time.Date(mid.Year(), mid.Month(), mid.Day(), 0, 0, 0, 0, time.UTC).Add(time.Duration(noonUTC * float64(time.Hour)))
	if diff := noon.Sub(mid); diff > 12*time.Hour {
		noon = noon.Add(-24 * time.Hour)
	} else if diff < -12*time.Hour {
		noon = noon.Add(24 * time.Hour)
	}
	half := time.Duration(dl / 2 * float64(time.Hour))
	return noon.Add(-half).In(loc).Truncate(time.Minute), noon.Add(half).In(loc).Truncate(time.Minute)
}

func (x wx) isDay(t time.Time) float64 {
	sh := x.solarHour(t)
	dl := x.dayLength(t)
	if sh >= 12-dl/2 && sh <= 12+dl/2 {
		return 1
	}
	return 0
}

func (x wx) precip(t time.Time) float64 {
	c := x.dayCode(t)
	if c < 51 {
		return 0
	}
	f := hash01("p", t.UTC().Format(time.RFC3339), x.lat)
	if f < 0.5 {
		return 0
	}
	scale := 0.4
	if c >= 61 {
		scale = 1.6
	}
	if c >= 80 {
		scale = 3
	}
	return math.Round(f*scale*10) / 10
}

// hourly-style value for any variable at instant t.
func (x wx) value(name string, t time.Time) float64 {
	n := strings.ToLower(name)
	r := hash01(n, t.UTC().Format(time.RFC3339), x.lat, x.lon)
	switch {
	case strings.Contains(n, "apparent_temperature"):
		return x.temp(t) - 1.5 + r
	case strings.HasPrefix(n, "dew_point") || strings.HasPrefix(n, "dewpoint"):
		return x.temp(t) - 4 - 2*r
	case strings.Contains(n, "soil_temperature"):
		return x.tempMean(t) + r
	case strings.Contains(n, "temperature") || n == "temperature":
		return x.temp(t)
	case strings.Contains(n, "humidity"):
		return math.Round(70 - 15*math.Cos(2*math.Pi*(x.solarHour(t)-14)/24) + 10*r)
	case strings.Contains(n, "probability"):
		if x.dayCode(t) >= 51 {
			return math.Round(40 + 50*r)
		}
		return math.Round(10 * r)
	case strings.Contains(n, "weather_code") || strings.Contains(n, "weathercode"):
		return float64(x.dayCode(t))
	case strings.Contains(n, "cloud"):
		c := x.dayCode(t)
		switch {
		case c == 0:
			return math.Round(10 * r)
		case c <= 2:
			return math.Round(30 + 30*r)
		}
		return math.Round(80 + 20*r)
	case strings.Contains(n, "direction"):
		return math.Round(math.Mod(hash01("dir", x.dayKey(t), x.lat)*360+40*r, 360))
	case strings.Contains(n, "gust"):
		return math.Round((15+15*r)*10) / 10
	case strings.Contains(n, "wind"):
		return math.Round((3+12*r)*10) / 10
	case strings.Contains(n, "snow"):
		if x.temp(t) < 1 {
			return x.precip(t) * 0.7
		}
		return 0
	case strings.Contains(n, "showers"):
		if x.dayCode(t) >= 80 {
			return x.precip(t)
		}
		return 0
	case strings.Contains(n, "precipitation") || strings.Contains(n, "rain"):
		return x.precip(t)
	case strings.Contains(n, "surface_pressure"):
		return 1012 - 3*r - 0.1*hash01("elev", x.lat)
	case strings.Contains(n, "pressure"):
		return 1013 + 6*(hash01("pr", x.dayKey(t))-0.5) + r
	case n == "is_day":
		return x.isDay(t)
	case strings.HasPrefix(n, "uv_index"):
		return math.Round(math.Max(0, 6*math.Cos(2*math.Pi*(x.solarHour(t)-12)/24)*x.isDay(t)-r)*100) / 100
	case n == "visibility":
		return 24140 - 8000*r
	case strings.Contains(n, "radiation") || strings.Contains(n, "irradiance"):
		return math.Round(math.Max(0, 600*math.Cos(2*math.Pi*(x.solarHour(t)-12)/24))*x.isDay(t)*10) / 10
	case strings.Contains(n, "sunshine_duration"):
		return 3600 * x.isDay(t) * (0.3 + 0.7*r)
	case strings.Contains(n, "evapotranspiration"):
		return 0.05 + 0.1*r*x.isDay(t)
	case strings.Contains(n, "soil_moisture"):
		return 0.25 + 0.1*r
	case strings.Contains(n, "freezing_level"):
		return 3000 + 1000*r
	case strings.Contains(n, "cape"):
		return 200 * r
	}
	return math.Round(100*r) / 10
}

// daily aggregate value for variable name over the local day starting at d.
func (x wx) daily(name string, d time.Time) float64 {
	n := strings.ToLower(name)
	var hours []time.Time
	for h := 0; h < 24; h++ {
		hours = append(hours, d.Add(time.Duration(h)*time.Hour))
	}
	agg := func(base string, f func([]float64) float64) float64 {
		var vs []float64
		for _, t := range hours {
			vs = append(vs, x.value(base, t))
		}
		return f(vs)
	}
	mx := func(v []float64) float64 {
		m := v[0]
		for _, a := range v {
			m = math.Max(m, a)
		}
		return m
	}
	mn := func(v []float64) float64 {
		m := v[0]
		for _, a := range v {
			m = math.Min(m, a)
		}
		return m
	}
	sum := func(v []float64) float64 {
		s := 0.0
		for _, a := range v {
			s += a
		}
		return s
	}
	mean := func(v []float64) float64 { return sum(v) / float64(len(v)) }
	switch {
	case n == "daylight_duration":
		return x.dayLength(d) * 3600
	case n == "sunshine_duration":
		return x.dayLength(d) * 3600 * (0.2 + 0.6*hash01("sun", x.dayKey(d)))
	case strings.Contains(n, "weather_code") || strings.Contains(n, "weathercode"):
		return float64(x.dayCode(d.Add(12 * time.Hour)))
	case n == "precipitation_hours":
		c := 0.0
		for _, t := range hours {
			if x.precip(t) > 0 {
				c++
			}
		}
		return c
	}
	base := n
	for _, suf := range []string{"_max", "_min", "_mean", "_sum", "_dominant"} {
		base = strings.TrimSuffix(base, suf)
	}
	switch {
	case strings.HasSuffix(n, "_max"):
		return agg(base, mx)
	case strings.HasSuffix(n, "_min"):
		return agg(base, mn)
	case strings.HasSuffix(n, "_sum"):
		if strings.Contains(n, "radiation") {
			return agg(base, sum) * 3600 / 1e6
		}
		return agg(base, sum)
	}
	return agg(base, mean)
}

func convertUnit(v float64, spec varSpec, q url.Values) (float64, string) {
	unit := spec.unit
	switch spec.kind {
	case "temp":
		if q.Get("temperature_unit") == "fahrenheit" {
			return v*9/5 + 32, "°F"
		}
	case "wind":
		switch q.Get("wind_speed_unit") + q.Get("windspeed_unit") {
		case "ms":
			return v / 3.6, "m/s"
		case "mph":
			return v / 1.609344, "mp/h"
		case "kn":
			return v / 1.852, "kn"
		}
	case "precip":
		if q.Get("precipitation_unit") == "inch" {
			return v / 25.4, "inch"
		}
	case "snow":
		if q.Get("precipitation_unit") == "inch" {
			return v / 2.54, "inch"
		}
	}
	return v, unit
}

func splitList(q url.Values, key string) []string {
	var out []string
	for _, v := range q[key] {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func tzAbbrev(off int) string {
	if off == 0 {
		return "GMT"
	}
	s := fmt.Sprintf("GMT%+d", off/3600)
	if m := (abs(off) % 3600) / 60; m != 0 {
		s += fmt.Sprintf(":%02d", m)
	}
	return s
}

func abs(i int) int {
	if i < 0 {
		return -i
	}
	return i
}

func autoTZ(lat, lon float64) string {
	best, bd := "", 1e9
	for _, p := range places {
		d := math.Hypot(p.Lat-lat, p.Lon-lon)
		if d < bd {
			best, bd = p.TZ, d
		}
	}
	if bd < 5 {
		return best
	}
	off := int(math.Round(lon / 15))
	if off == 0 {
		return "GMT"
	}
	// Etc/GMT signs are inverted.
	return fmt.Sprintf("Etc/GMT%+d", -off)
}

func forecast(w http.ResponseWriter, r *http.Request, rec *logRec) {
	start := time.Now()
	if r.URL.Path != "/v1/forecast" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	lats, lons := splitList(q, "latitude"), splitList(q, "longitude")
	if len(lats) != len(lons) {
		omError(w, "Parameter 'latitude' and 'longitude' must have the same number of elements")
		return
	}
	if len(lats) == 0 {
		omError(w, "No value found (expected type 'Float') at path 'latitude'. No Float was found at 'latitude'.")
		return
	}
	days := 7
	if v := q.Get("forecast_days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 16 {
			omError(w, "Forecast days is invalid. Allowed range 0 to 16.")
			return
		}
		days = n
	}
	past := 0
	if v := q.Get("past_days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 92 {
			omError(w, "Past days is invalid. Allowed range 0 to 92.")
			return
		}
		past = n
	}
	tzs := splitList(q, "timezone")
	var results []obj
	for i := range lats {
		lat, err1 := strconv.ParseFloat(lats[i], 64)
		lon, err2 := strconv.ParseFloat(lons[i], 64)
		if err1 != nil || err2 != nil || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
			omError(w, fmt.Sprintf("Latitude must be in range of -90 to 90°. Given: %s.", lats[i]))
			return
		}
		tzName := "GMT"
		if len(tzs) > 0 {
			tzName = tzs[0]
			if i < len(tzs) {
				tzName = tzs[i]
			}
		}
		o, err := forecastOne(q, lat, lon, tzName, days, past, start)
		if err != "" {
			omError(w, err)
			return
		}
		results = append(results, o)
	}
	rec.Note = fmt.Sprintf("days=%d current=%v daily=%v hourly=%v", days, splitList(q, "current"), splitList(q, "daily"), splitList(q, "hourly"))
	if len(results) == 1 {
		writeJSON(w, 200, results[0])
		return
	}
	writeJSON(w, 200, results)
}

func forecastOne(q url.Values, lat, lon float64, tzName string, days, past int, start time.Time) (obj, string) {
	if strings.EqualFold(tzName, "auto") {
		tzName = autoTZ(lat, lon)
	}
	var loc *time.Location
	if tzName == "GMT" || tzName == "UTC" {
		loc = time.UTC
	} else {
		l, err := time.LoadLocation(tzName)
		if err != nil {
			return nil, "Invalid timezone"
		}
		loc = l
	}
	x := wx{lat, lon}
	now := time.Now().In(loc)
	_, off := now.Zone()
	unix := q.Get("timeformat") == "unixtime"
	timeUnit := "iso8601"
	if unix {
		timeUnit = "unixtime"
	}
	fmtTime := func(t time.Time, dateOnly bool) any {
		if unix {
			return t.Unix()
		}
		if dateOnly {
			return t.In(loc).Format("2006-01-02")
		}
		return t.In(loc).Format("2006-01-02T15:04")
	}
	elev := 10.0
	for _, p := range places {
		if math.Hypot(p.Lat-lat, p.Lon-lon) < 0.3 {
			elev = p.Elevation + 7
		}
	}
	if v := q.Get("elevation"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			elev = f
		}
	}
	snap := func(v float64) float64 { return math.Round(math.Round(v/0.0625)*0.0625*100000) / 100000 }
	o := obj{}
	o.set("latitude", snap(lat))
	o.set("longitude", snap(lon))
	o.set("generationtime_ms", float64(time.Since(start).Microseconds())/1000+0.05)
	o.set("utc_offset_seconds", off)
	tzOut := tzName
	if loc == time.UTC {
		tzOut = "GMT"
	}
	o.set("timezone", tzOut)
	o.set("timezone_abbreviation", tzAbbrev(off))
	o.set("elevation", num{elev, 1})

	y, m, d := now.Date()
	day0 := time.Date(y, m, d, 0, 0, 0, 0, loc).AddDate(0, 0, -past)
	cur := now.Truncate(15 * time.Minute)
	// Truncate works on absolute time; realign to local quarter hours.
	cur = time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute()/15*15, 0, 0, loc)

	if cw := q.Get("current_weather"); cw == "true" || cw == "1" {
		u := obj{}
		c := obj{}
		u.set("time", timeUnit)
		c.set("time", fmtTime(cur, false))
		u.set("interval", "seconds")
		c.set("interval", 900)
		tv, tu := convertUnit(x.value("temperature_2m", cur), specFor("temperature_2m"), q)
		u.set("temperature", tu)
		c.set("temperature", num{tv, 1})
		wv, wu := convertUnit(x.value("wind_speed_10m", cur), specFor("wind_speed_10m"), q)
		u.set("windspeed", wu)
		c.set("windspeed", num{wv, 1})
		u.set("winddirection", "°")
		c.set("winddirection", int(x.value("wind_direction_10m", cur)))
		u.set("is_day", "")
		c.set("is_day", int(x.isDay(cur)))
		u.set("weathercode", "wmo code")
		c.set("weathercode", x.dayCode(cur))
		o.set("current_weather_units", u)
		o.set("current_weather", c)
	}
	if vars := splitList(q, "current"); len(vars) > 0 {
		u := obj{}
		c := obj{}
		u.set("time", timeUnit)
		c.set("time", fmtTime(cur, false))
		u.set("interval", "seconds")
		c.set("interval", 900)
		for _, v := range vars {
			sp := specFor(v)
			val, unit := convertUnit(x.value(v, cur), sp, q)
			u.set(v, unit)
			c.set(v, num{val, sp.dec})
		}
		o.set("current_units", u)
		o.set("current", c)
	}
	if vars := splitList(q, "hourly"); len(vars) > 0 {
		n := (days + past) * 24
		u := obj{}
		hv := obj{}
		u.set("time", timeUnit)
		times := make([]any, 0, n)
		var instants []time.Time
		for i := 0; i < n; i++ {
			t := day0.Add(time.Duration(i) * time.Hour)
			instants = append(instants, t)
			times = append(times, fmtTime(t, false))
		}
		hv.set("time", times)
		for _, v := range vars {
			sp := specFor(v)
			arr := make([]any, 0, n)
			unit := sp.unit
			for _, t := range instants {
				val, un := convertUnit(x.value(v, t), sp, q)
				unit = un
				arr = append(arr, num{val, sp.dec})
			}
			u.set(v, unit)
			hv.set(v, arr)
		}
		o.set("hourly_units", u)
		o.set("hourly", hv)
	}
	if vars := splitList(q, "daily"); len(vars) > 0 {
		n := days + past
		u := obj{}
		dv := obj{}
		u.set("time", timeUnit)
		var dates []time.Time
		times := make([]any, 0, n)
		for i := 0; i < n; i++ {
			dd := day0.AddDate(0, 0, i)
			dates = append(dates, dd)
			times = append(times, fmtTime(dd, true))
		}
		dv.set("time", times)
		for _, v := range vars {
			sp := specFor(v)
			arr := make([]any, 0, n)
			unit := sp.unit
			if strings.ToLower(v) == "precipitation_hours" {
				sp = varSpec{"h", 1, "other"}
				unit = "h"
			}
			for _, dd := range dates {
				if sp.kind == "time" {
					sr, ss := x.sun(dd, loc)
					t := sr
					if strings.ToLower(v) == "sunset" {
						t = ss
					}
					arr = append(arr, fmtTime(t, false))
					unit = timeUnit
					continue
				}
				val, un := convertUnit(x.daily(v, dd), sp, q)
				unit = un
				arr = append(arr, num{val, sp.dec})
			}
			u.set(v, unit)
			dv.set(v, arr)
		}
		o.set("daily_units", u)
		o.set("daily", dv)
	}
	return o, ""
}

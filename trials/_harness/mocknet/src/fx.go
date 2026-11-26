package main

import (
	_ "embed"
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const fxValidKey = "TRIAL-FX-KEY-7f3a91"

//go:embed rates_usd.json
var ratesJSON []byte

var usdRates map[string]float64
var fxCodes []string

var currencyNames = map[string]string{
	"USD": "United States Dollar", "TWD": "New Taiwan Dollar", "JPY": "Japanese Yen", "EUR": "Euro",
	"GBP": "Pound Sterling", "KRW": "South Korean Won", "HKD": "Hong Kong Dollar", "CNY": "Chinese Renminbi",
	"THB": "Thai Baht", "SGD": "Singapore Dollar", "AUD": "Australian Dollar", "CAD": "Canadian Dollar",
	"CHF": "Swiss Franc", "NZD": "New Zealand Dollar", "MYR": "Malaysian Ringgit", "PHP": "Philippine Peso",
	"VND": "Vietnamese Đồng", "IDR": "Indonesian Rupiah", "INR": "Indian Rupee", "MOP": "Macanese Pataca",
}

func init() {
	if err := json.Unmarshal(ratesJSON, &usdRates); err != nil {
		panic(err)
	}
	for c := range usdRates {
		fxCodes = append(fxCodes, c)
	}
	sort.Strings(fxCodes)
}

func fxRound(v float64) num {
	if v != 0 && math.Abs(v) < 0.01 {
		return num{v, 6}
	}
	return num{math.Round(v*10000) / 10000, 4}
}

func fxHeader(o *obj) {
	now := time.Now().UTC()
	last := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 1, 0, time.UTC)
	next := last.Add(24 * time.Hour)
	o.set("result", "success")
	o.set("documentation", "https://www.exchangerate-api.com/docs")
	o.set("terms_of_use", "https://www.exchangerate-api.com/terms")
	o.set("time_last_update_unix", last.Unix())
	o.set("time_last_update_utc", last.Format("Mon, 02 Jan 2006 15:04:05 -0700"))
	o.set("time_next_update_unix", next.Unix())
	o.set("time_next_update_utc", next.Format("Mon, 02 Jan 2006 15:04:05 -0700"))
}

func fxError(w http.ResponseWriter, status int, typ string) {
	o := obj{}
	o.set("result", "error")
	o.set("documentation", "https://www.exchangerate-api.com/docs")
	o.set("terms-of-use", "https://www.exchangerate-api.com/terms")
	o.set("error-type", typ)
	writeJSON(w, status, o)
}

var fxEndpoints = map[string]bool{"latest": true, "pair": true, "codes": true, "quota": true, "enriched": true, "history": true}

func exchange(w http.ResponseWriter, r *http.Request, rec *logRec) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(segs) < 2 || segs[0] != "v6" {
		fxError(w, http.StatusNotFound, "malformed-request")
		return
	}
	segs = segs[1:]
	var key, via string
	if fxEndpoints[segs[0]] {
		// Key in the Authorization header: /v6/latest/USD
		if a := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(a), "bearer ") {
			key, via = strings.TrimSpace(a[7:]), "authorization-bearer"
		} else {
			via = "none"
		}
	} else {
		key, via = segs[0], "url-path"
		segs = segs[1:]
	}
	if !keyInfo(rec, via, key, fxValidKey) {
		fxError(w, http.StatusForbidden, "invalid-key")
		return
	}
	if len(segs) == 0 {
		fxError(w, http.StatusNotFound, "malformed-request")
		return
	}
	code := func(s string) (string, bool) {
		s = strings.ToUpper(s)
		_, ok := usdRates[s]
		return s, ok
	}
	switch segs[0] {
	case "latest":
		if len(segs) != 2 {
			fxError(w, http.StatusNotFound, "malformed-request")
			return
		}
		base, ok := code(segs[1])
		if !ok {
			fxError(w, http.StatusNotFound, "unsupported-code")
			return
		}
		o := obj{}
		fxHeader(&o)
		o.set("base_code", base)
		rates := obj{}
		rates.set(base, 1)
		for _, c := range fxCodes {
			if c != base {
				rates.set(c, fxRound(usdRates[c]/usdRates[base]))
			}
		}
		o.set("conversion_rates", rates)
		rec.Note = "latest base=" + base
		writeJSON(w, 200, o)
	case "pair":
		if len(segs) != 3 && len(segs) != 4 {
			fxError(w, http.StatusNotFound, "malformed-request")
			return
		}
		a, ok1 := code(segs[1])
		b, ok2 := code(segs[2])
		if !ok1 || !ok2 {
			fxError(w, http.StatusNotFound, "unsupported-code")
			return
		}
		rate := usdRates[b] / usdRates[a]
		o := obj{}
		fxHeader(&o)
		o.set("base_code", a)
		o.set("target_code", b)
		o.set("conversion_rate", fxRound(rate))
		rec.Note = "pair " + a + "/" + b
		if len(segs) == 4 {
			amt, err := strconv.ParseFloat(segs[3], 64)
			if err != nil {
				fxError(w, http.StatusBadRequest, "malformed-request")
				return
			}
			o.set("conversion_result", fxRound(math.Round(rate*10000)/10000*amt))
			rec.Note += " amount=" + segs[3]
		}
		writeJSON(w, 200, o)
	case "codes":
		o := obj{}
		o.set("result", "success")
		o.set("documentation", "https://www.exchangerate-api.com/docs")
		o.set("terms_of_use", "https://www.exchangerate-api.com/terms")
		var list [][2]string
		for _, c := range fxCodes {
			n := currencyNames[c]
			if n == "" {
				n = c
			}
			list = append(list, [2]string{c, n})
		}
		o.set("supported_codes", list)
		writeJSON(w, 200, o)
	case "quota":
		o := obj{}
		o.set("result", "success")
		o.set("documentation", "https://www.exchangerate-api.com/docs")
		o.set("terms_of_use", "https://www.exchangerate-api.com/terms")
		o.set("plan_quota", 30000)
		o.set("requests_remaining", 29876)
		o.set("refresh_day_of_month", 17)
		writeJSON(w, 200, o)
	case "enriched", "history":
		fxError(w, http.StatusForbidden, "plan-upgrade-required")
	default:
		fxError(w, http.StatusNotFound, "malformed-request")
	}
}

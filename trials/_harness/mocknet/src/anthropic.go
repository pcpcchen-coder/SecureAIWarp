package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
	"unicode"
)

const anthropicValidKey = "sk-ant-trial-4c1e88d2"

const b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func b58id(prefix string, n int) string {
	var sb strings.Builder
	sb.WriteString(prefix)
	for i := 0; i < n; i++ {
		sb.WriteByte(b58[rand.Intn(len(b58))])
	}
	return sb.String()
}

func anthErr(w http.ResponseWriter, status int, typ, msg string) {
	rid := b58id("req_011Ch", 15)
	w.Header().Set("request-id", rid)
	if status == 401 {
		w.Header().Set("x-should-retry", "false")
	}
	e := obj{}
	e.set("type", typ)
	e.set("message", msg)
	o := obj{}
	o.set("type", "error")
	o.set("error", e)
	o.set("request_id", rid)
	writeJSON(w, status, o)
}

// estTokens: CJK runes ~1 token each, other text ~4 chars per token.
func estTokens(s string) int {
	cjk, other := 0, 0
	for _, r := range s {
		if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hangul, r) {
			cjk++
		} else {
			other++
		}
	}
	return cjk + (other+3)/4
}

// textOf flattens a content value (string or array of blocks).
func textOf(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		var parts []string
		for _, b := range c {
			m, ok := b.(map[string]any)
			if !ok {
				continue
			}
			switch m["type"] {
			case "text":
				if s, ok := m["text"].(string); ok {
					parts = append(parts, s)
				}
			case "tool_result":
				parts = append(parts, textOf(m["content"]))
			case "document":
				if src, ok := m["source"].(map[string]any); ok {
					if s, ok := src["data"].(string); ok && src["type"] == "text" {
						parts = append(parts, s)
					}
				}
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func summaryText(model, system, lastUser string, nMsgs int) string {
	var lines []string
	for _, l := range strings.Split(lastUser, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	chars := len([]rune(lastUser))
	var sb strings.Builder
	sb.WriteString("## 摘要\n\n")
	fmt.Fprintf(&sb, "已閱讀您提供的內容（共 %d 行、約 %d 字，對話中有 %d 則訊息）。以下是重點整理：\n\n", len(lines), chars, nMsgs)
	if len(lines) > 0 {
		sb.WriteString("### 開頭摘錄\n\n")
		for i, l := range lines {
			if i >= 3 {
				break
			}
			fmt.Fprintf(&sb, "> %s\n", trunc(l, 60))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("### 重點\n\n")
	if len(lines) > 0 {
		fmt.Fprintf(&sb, "- **主題**：內容以「%s」開頭，整體圍繞同一主題展開。\n", trunc(lines[0], 24))
	} else {
		sb.WriteString("- **主題**：輸入沒有文字內容。\n")
	}
	if len(lines) > 1 {
		fmt.Fprintf(&sb, "- **細節**：共 %d 個段落或項目，其中「%s」值得留意。\n", len(lines), trunc(lines[len(lines)/2], 24))
	}
	sb.WriteString("- **待辦**：建議確認上述項目的負責人與完成期限。\n\n")
	sb.WriteString("### 結論\n\n整體而言內容條理清楚；若需要更完整的分析，請提供更多背景資訊。\n")
	if system != "" {
		fmt.Fprintf(&sb, "\n（已套用系統提示：%s）\n", trunc(strings.ReplaceAll(system, "\n", " "), 30))
	}
	return sb.String()
}

func anthropic(w http.ResponseWriter, r *http.Request, rec *logRec) {
	rec.Beta = r.Header.Get("anthropic-beta")
	// Credentials: x-api-key (SDK default) or Authorization: Bearer.
	xk := r.Header.Get("x-api-key")
	bearer := ""
	if a := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(a), "bearer ") {
		bearer = strings.TrimSpace(a[7:])
	}
	switch {
	case xk != "":
		via := "x-api-key"
		if bearer != "" {
			via = "x-api-key+authorization-bearer"
		}
		if !keyInfo(rec, via, xk, anthropicValidKey) {
			anthErr(w, 401, "authentication_error", "invalid x-api-key")
			return
		}
	case bearer != "":
		if !keyInfo(rec, "authorization-bearer", bearer, anthropicValidKey) {
			anthErr(w, 401, "authentication_error", "Invalid bearer token")
			return
		}
	default:
		keyInfo(rec, "none", "", anthropicValidKey)
		anthErr(w, 401, "authentication_error", "x-api-key header is required")
		return
	}

	if r.URL.Path == "/v1/models" && r.Method == http.MethodGet {
		var data []any
		for _, m := range []string{"claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"} {
			o := obj{}
			o.set("type", "model")
			o.set("id", m)
			o.set("display_name", m)
			o.set("created_at", "2026-01-01T00:00:00Z")
			data = append(data, o)
		}
		o := obj{}
		o.set("data", data)
		o.set("has_more", false)
		o.set("first_id", "claude-opus-5-5")
		o.set("last_id", "claude-haiku-5-5")
		writeJSON(w, 200, o)
		return
	}
	if r.Method != http.MethodPost || (r.URL.Path != "/v1/messages" && r.URL.Path != "/v1/messages/count_tokens") {
		anthErr(w, 404, "not_found_error", "Not Found")
		return
	}
	var body io.Reader = io.LimitReader(r.Body, 32<<20)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(body)
		if err != nil {
			anthErr(w, 400, "invalid_request_error", "Could not decompress request body")
			return
		}
		body = gz
	}
	raw, _ := io.ReadAll(body)
	var req map[string]any
	if err := json.Unmarshal(raw, &req); err != nil {
		anthErr(w, 400, "invalid_request_error", "There was an issue with the formatting or content of your request body: invalid JSON")
		return
	}
	model, _ := req["model"].(string)
	rec.Model = model
	msgs, _ := req["messages"].([]any)
	if model == "" {
		anthErr(w, 400, "invalid_request_error", "model: Field required")
		return
	}
	if req["messages"] == nil {
		anthErr(w, 400, "invalid_request_error", "messages: Field required")
		return
	}
	system := textOf(req["system"])
	var all strings.Builder
	all.WriteString(system)
	lastUser := ""
	for _, m := range msgs {
		mm, _ := m.(map[string]any)
		t := textOf(mm["content"])
		all.WriteString("\n" + t)
		if mm["role"] == "user" {
			lastUser = t
		}
	}
	if tools, ok := req["tools"].([]any); ok {
		tb, _ := json.Marshal(tools)
		all.Write(tb)
	}
	inTok := estTokens(all.String()) + 3*len(msgs) + 4
	if r.URL.Path == "/v1/messages/count_tokens" {
		o := obj{}
		o.set("input_tokens", inTok)
		w.Header().Set("request-id", b58id("req_011Ch", 15))
		writeJSON(w, 200, o)
		return
	}
	maxTok := 0
	if v, ok := req["max_tokens"].(float64); ok {
		maxTok = int(v)
	} else {
		anthErr(w, 400, "invalid_request_error", "max_tokens: Field required")
		return
	}
	if maxTok < 1 {
		anthErr(w, 400, "invalid_request_error", "max_tokens: Input should be greater than or equal to 1")
		return
	}
	text := summaryText(model, system, lastUser, len(msgs))
	stop := "end_turn"
	if estTokens(text) > maxTok {
		rs := []rune(text)
		for len(rs) > 0 && estTokens(string(rs)) > maxTok {
			rs = rs[:len(rs)*9/10]
		}
		text = string(rs)
		stop = "max_tokens"
	}
	outTok := estTokens(text)
	msgID := b58id("msg_01", 22)
	rid := b58id("req_011Ch", 15)
	w.Header().Set("request-id", rid)
	w.Header().Set("anthropic-organization-id", "00000000-0000-4000-8000-000000000000")
	stream, _ := req["stream"].(bool)
	rec.Stream = stream
	rec.Note = fmt.Sprintf("in_tokens~%d out_tokens~%d stop=%s", inTok, outTok, stop)

	usage := func(out int, includeService bool) obj {
		u := obj{}
		u.set("input_tokens", inTok)
		u.set("cache_creation_input_tokens", 0)
		u.set("cache_read_input_tokens", 0)
		u.set("output_tokens", out)
		if includeService {
			u.set("service_tier", "standard")
		}
		return u
	}
	if !stream {
		blk := obj{}
		blk.set("type", "text")
		blk.set("text", text)
		o := obj{}
		o.set("id", msgID)
		o.set("type", "message")
		o.set("role", "assistant")
		o.set("model", model)
		o.set("content", []any{blk})
		o.set("stop_reason", stop)
		o.set("stop_sequence", nil)
		o.set("usage", usage(outTok, true))
		writeJSON(w, 200, o)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	fl, _ := w.(http.Flusher)
	send := func(ev string, data any) {
		b, _ := marshalNoEscape(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev, b)
		if fl != nil {
			fl.Flush()
		}
	}
	start := obj{}
	start.set("id", msgID)
	start.set("type", "message")
	start.set("role", "assistant")
	start.set("model", model)
	start.set("content", []any{})
	start.set("stop_reason", nil)
	start.set("stop_sequence", nil)
	start.set("usage", usage(1, true))
	ms := obj{}
	ms.set("type", "message_start")
	ms.set("message", start)
	send("message_start", ms)
	cb := obj{}
	cb.set("type", "text")
	cb.set("text", "")
	cbs := obj{}
	cbs.set("type", "content_block_start")
	cbs.set("index", 0)
	cbs.set("content_block", cb)
	send("content_block_start", cbs)
	send("ping", obj{{"type", "ping"}})
	rs := []rune(text)
	for i := 0; i < len(rs); i += 12 {
		j := i + 12
		if j > len(rs) {
			j = len(rs)
		}
		d := obj{}
		d.set("type", "text_delta")
		d.set("text", string(rs[i:j]))
		ev := obj{}
		ev.set("type", "content_block_delta")
		ev.set("index", 0)
		ev.set("delta", d)
		send("content_block_delta", ev)
		select {
		case <-time.After(15 * time.Millisecond):
		case <-r.Context().Done():
			rec.Note += " (client disconnected mid-stream)"
			return
		}
	}
	send("content_block_stop", obj{{"type", "content_block_stop"}, {"index", 0}})
	md := obj{}
	md.set("type", "message_delta")
	md.set("delta", obj{{"stop_reason", stop}, {"stop_sequence", nil}})
	md.set("usage", usage(outTok, false))
	send("message_delta", md)
	send("message_stop", obj{{"type", "message_stop"}})
}

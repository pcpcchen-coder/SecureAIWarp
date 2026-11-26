package main

import (
	"html"
	"regexp"
	"strings"
)

// rawLink is a link destination found in a Markdown document, with the
// 1-based line number it appears on.
type rawLink struct {
	Line int
	URL  string
}

var (
	refDefRe   = regexp.MustCompile(`^ {0,3}\[[^\]]+\]:[ \t]*(<[^>]*>|\S+)`)
	autolinkRe = regexp.MustCompile(`<((?i:https?)://[^>\s]+)>`)
	htmlTagRe  = regexp.MustCompile(`<[a-zA-Z][a-zA-Z0-9-]*(?:\s[^>]*)?/?>`)
	htmlAttrRe = regexp.MustCompile(`(?i)\s(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	bareURLRe  = regexp.MustCompile(`(?i)\bhttps?://[^\s<>\[\]()"'\x60]+`)
)

// documentLines splits Markdown source into lines and reports, for each line,
// whether it is ordinary content (true) or belongs to YAML front matter or a
// fenced code block (false). Fence delimiter lines are reported as false.
func documentLines(src string) ([]string, []bool) {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	lines := strings.Split(src, "\n")
	content := make([]bool, len(lines))

	start := 0
	if len(lines) > 0 && strings.TrimRight(lines[0], " \t") == "---" {
		for i := 1; i < len(lines); i++ {
			t := strings.TrimRight(lines[i], " \t")
			if t == "---" || t == "..." {
				start = i + 1
				break
			}
		}
	}

	inFence := false
	var fenceChar byte
	fenceLen := 0
	for i := start; i < len(lines); i++ {
		ch, n, rest, ok := fenceMarker(lines[i])
		if ok {
			if !inFence {
				inFence, fenceChar, fenceLen = true, ch, n
				continue
			}
			if ch == fenceChar && n >= fenceLen && strings.TrimSpace(rest) == "" {
				inFence = false
				continue
			}
		}
		if !inFence {
			content[i] = true
		}
	}
	return lines, content
}

// fenceMarker reports whether line starts a code fence (``` or ~~~),
// returning the fence character, its run length and the remaining text.
func fenceMarker(line string) (byte, int, string, bool) {
	indent := 0
	for indent < len(line) && indent < 4 && line[indent] == ' ' {
		indent++
	}
	if indent > 3 || indent >= len(line) {
		return 0, 0, "", false
	}
	ch := line[indent]
	if ch != '`' && ch != '~' {
		return 0, 0, "", false
	}
	n := 0
	for indent+n < len(line) && line[indent+n] == ch {
		n++
	}
	if n < 3 {
		return 0, 0, "", false
	}
	return ch, n, line[indent+n:], true
}

// extractLinks returns every link destination in a Markdown document:
// inline links and images, reference definitions, <autolinks>, HTML
// href/src attributes and bare http(s) URLs. Code blocks, code spans,
// HTML comments and front matter are ignored.
func extractLinks(src string) []rawLink {
	lines, content := documentLines(src)
	var out []rawLink
	inComment := false
	for i, line := range lines {
		if !content[i] {
			continue
		}
		line = stripHTMLComments(line, &inComment)
		line = blankCodeSpans(line)
		for _, u := range linksInLine(line) {
			out = append(out, rawLink{Line: i + 1, URL: u})
		}
	}
	return out
}

// stripHTMLComments removes <!-- ... --> regions, which may span lines.
func stripHTMLComments(line string, inComment *bool) string {
	var b strings.Builder
	for {
		if *inComment {
			end := strings.Index(line, "-->")
			if end < 0 {
				return b.String()
			}
			line = line[end+3:]
			*inComment = false
			continue
		}
		start := strings.Index(line, "<!--")
		if start < 0 {
			b.WriteString(line)
			return b.String()
		}
		b.WriteString(line[:start])
		line = line[start+4:]
		*inComment = true
	}
}

// blankCodeSpans replaces `code spans` with spaces so links inside them are
// not reported. The line length is preserved.
func blankCodeSpans(line string) string {
	b := []byte(line)
	i := 0
	for i < len(b) {
		if b[i] != '`' {
			i++
			continue
		}
		n := 0
		for i+n < len(b) && b[i+n] == '`' {
			n++
		}
		// Look for a closing run of exactly n backticks.
		j := i + n
		closed := -1
		for j < len(b) {
			if b[j] != '`' {
				j++
				continue
			}
			m := 0
			for j+m < len(b) && b[j+m] == '`' {
				m++
			}
			if m == n {
				closed = j + m
				break
			}
			j += m
		}
		if closed < 0 {
			i += n
			continue
		}
		for k := i; k < closed; k++ {
			b[k] = ' '
		}
		i = closed
	}
	return string(b)
}

func maskRange(b []byte, start, end int) {
	for k := start; k < end && k < len(b); k++ {
		b[k] = ' '
	}
}

// linksInLine extracts link destinations from a single line of content.
func linksInLine(line string) []string {
	if m := refDefRe.FindStringSubmatch(line); m != nil {
		return []string{cleanDest(m[1])}
	}

	var out []string
	buf := []byte(line)

	// Autolinks: <https://example.com>.
	for _, loc := range autolinkRe.FindAllSubmatchIndex(buf, -1) {
		out = append(out, string(buf[loc[2]:loc[3]]))
		maskRange(buf, loc[0], loc[1])
	}

	// Inline links and images: [text](dest "title"), ![alt](dest).
	pos := 0
	for {
		rel := strings.Index(string(buf[pos:]), "](")
		if rel < 0 {
			break
		}
		idx := pos + rel
		open := strings.LastIndexByte(string(buf[:idx]), '[')
		dest, end := parseDest(buf, idx+2)
		if open < 0 || dest == "" {
			pos = idx + 2
			continue
		}
		out = append(out, cleanDest(dest))
		maskRange(buf, open, end)
		pos = end
	}

	// HTML tags: <a href="...">, <img src="...">.
	for _, loc := range htmlTagRe.FindAllStringIndex(string(buf), -1) {
		tag := string(buf[loc[0]:loc[1]])
		for _, am := range htmlAttrRe.FindAllStringSubmatch(tag, -1) {
			v := am[1]
			if v == "" {
				v = am[2]
			}
			if v = strings.TrimSpace(html.UnescapeString(v)); v != "" {
				out = append(out, v)
			}
		}
		maskRange(buf, loc[0], loc[1])
	}

	// Bare URLs (GitHub-style autolink extension).
	for _, m := range bareURLRe.FindAllString(string(buf), -1) {
		m = strings.TrimRight(m, ".,;:!?*_~")
		if m != "" {
			out = append(out, m)
		}
	}
	return out
}

// parseDest parses an inline link destination starting at buf[i] (just after
// "]("). It returns the raw destination and the index just past the closing
// parenthesis (or the end of what was consumed).
func parseDest(buf []byte, i int) (string, int) {
	for i < len(buf) && (buf[i] == ' ' || buf[i] == '\t') {
		i++
	}
	if i >= len(buf) {
		return "", i
	}
	var dest string
	if buf[i] == '<' {
		end := strings.IndexByte(string(buf[i:]), '>')
		if end < 0 {
			return "", i + 1
		}
		dest = string(buf[i : i+end+1])
		i += end + 1
	} else {
		start := i
		depth := 0
	loop:
		for i < len(buf) {
			switch c := buf[i]; {
			case c == '\\' && i+1 < len(buf):
				i += 2
				continue
			case c == ' ' || c == '\t':
				break loop
			case c == '(':
				depth++
			case c == ')':
				if depth == 0 {
					break loop
				}
				depth--
			}
			i++
		}
		dest = string(buf[start:i])
	}
	// Skip an optional title and find the closing parenthesis.
	if close := strings.IndexByte(string(buf[i:]), ')'); close >= 0 {
		i += close + 1
	} else {
		i = len(buf)
	}
	return dest, i
}

// cleanDest removes angle brackets and backslash escapes from a destination.
func cleanDest(d string) string {
	d = strings.TrimSpace(d)
	if strings.HasPrefix(d, "<") && strings.HasSuffix(d, ">") {
		d = d[1 : len(d)-1]
	}
	if strings.Contains(d, `\`) {
		var b strings.Builder
		for i := 0; i < len(d); i++ {
			if d[i] == '\\' && i+1 < len(d) && strings.IndexByte("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", d[i+1]) >= 0 {
				i++
			}
			b.WriteByte(d[i])
		}
		d = b.String()
	}
	return html.UnescapeString(d)
}

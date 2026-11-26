package main

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	atxHeadingRe    = regexp.MustCompile(`^ {0,3}#{1,6}(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$`)
	setextRe        = regexp.MustCompile(`^ {0,3}(?:=+|-+)[ \t]*$`)
	customIDRe      = regexp.MustCompile(`[ \t]*\{#([^}\s]+)[^}]*\}[ \t]*$`)
	htmlIDRe        = regexp.MustCompile(`(?i)<[a-z][a-z0-9]*\b[^>]*?\s(?:id|name)\s*=\s*(?:"([^"]+)"|'([^']+)')`)
	mdImageRe       = regexp.MustCompile(`!\[([^\]]*)\]\([^)]*\)`)
	mdInlineLinkRe  = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	mdRefLinkRe     = regexp.MustCompile(`\[([^\]]*)\]\[[^\]]*\]`)
	htmlAnyTagRe    = regexp.MustCompile(`<[^>]+>`)
	listOrQuoteLine = regexp.MustCompile(`^ {0,3}(?:[-*+>]|\d+[.)])(?:[ \t]|$)`)
)

// collectAnchors returns the set of anchors a Markdown document defines:
// GitHub-style heading slugs (with -1, -2 suffixes for duplicates), explicit
// {#custom-id} heading attributes and HTML id/name attributes.
func collectAnchors(src string) map[string]bool {
	lines, content := documentLines(src)
	anchors := map[string]bool{}
	seen := map[string]int{}

	addHeading := func(text string) {
		if m := customIDRe.FindStringSubmatch(text); m != nil {
			anchors[m[1]] = true
			text = text[:len(text)-len(m[0])]
		}
		slug := slugify(text)
		n := seen[slug]
		seen[slug] = n + 1
		if n > 0 {
			slug = slug + "-" + strconv.Itoa(n)
		}
		anchors[slug] = true
	}

	for i, line := range lines {
		if !content[i] {
			continue
		}
		for _, m := range htmlIDRe.FindAllStringSubmatch(blankCodeSpans(line), -1) {
			id := m[1]
			if id == "" {
				id = m[2]
			}
			anchors[id] = true
		}
		if m := atxHeadingRe.FindStringSubmatch(line); m != nil {
			addHeading(m[1])
			continue
		}
		// Setext heading: a paragraph line followed by === or ---.
		if i+1 < len(lines) && content[i+1] && strings.TrimSpace(line) != "" &&
			setextRe.MatchString(lines[i+1]) && !listOrQuoteLine.MatchString(line) &&
			!strings.HasPrefix(line, "    ") {
			addHeading(strings.TrimSpace(line))
		}
	}
	return anchors
}

// slugify converts heading text to an anchor the way GitHub does: inline
// Markdown is reduced to its text, the result is lower-cased, punctuation is
// dropped and spaces become hyphens. Non-ASCII letters (e.g. CJK) are kept.
func slugify(text string) string {
	text = mdImageRe.ReplaceAllString(text, "$1")
	text = mdInlineLinkRe.ReplaceAllString(text, "$1")
	text = mdRefLinkRe.ReplaceAllString(text, "$1")
	text = htmlAnyTagRe.ReplaceAllString(text, "")
	text = strings.ToLower(strings.TrimSpace(text))

	var b strings.Builder
	for _, r := range text {
		switch {
		case unicode.IsLetter(r), unicode.IsNumber(r), unicode.Is(unicode.Mn, r), r == '_', r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}

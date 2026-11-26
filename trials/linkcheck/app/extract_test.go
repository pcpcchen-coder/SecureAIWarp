package main

import (
	"reflect"
	"strings"
	"testing"
)

func spaces(n int) string { return strings.Repeat(" ", n) }

func TestExtractLinks(t *testing.T) {
	src := "---\n" +
		"title: [not](a-link.md)\n" +
		"---\n" +
		"# Title\n" +
		"See [guide](guide.md) and ![logo](img/logo.png \"Logo\").\n" +
		"Wiki: [Go](https://en.wikipedia.org/wiki/Go_(programming_language)).\n" +
		"Angle: [x](<path with space.md>) and <https://auto.example.com/x>.\n" +
		"Bare https://bare.example.com/page. end\n" +
		"`[code](ignored.md)` and ``https://ignored.example.com``\n" +
		"```md\n" +
		"[fenced](ignored.md)\n" +
		"```\n" +
		"<!-- [comment](ignored.md)\n" +
		"still comment https://ignored.example.com -->\n" +
		"<a href=\"html.md#sec\">a</a> <img src='pic.png'>\n" +
		"[ref]: https://ref.example.com/doc \"Title\"\n" +
		"[link text https://text.example.com](target.md)\n" +
		"[![badge](https://img.example.com/b.svg)](https://ci.example.com)\n" +
		"Escaped [e](a\\_b.md) and entity [q](x.md?a=1&amp;b=2)\n" +
		"~~~\n" +
		"https://ignored.example.com\n" +
		"~~~\n" +
		"[anchor](#title)\n"

	got := extractLinks(src)
	want := []rawLink{
		{5, "guide.md"},
		{5, "img/logo.png"},
		{6, "https://en.wikipedia.org/wiki/Go_(programming_language)"},
		{7, "https://auto.example.com/x"},
		{7, "path with space.md"},
		{8, "https://bare.example.com/page"},
		{15, "html.md#sec"},
		{15, "pic.png"},
		{16, "https://ref.example.com/doc"},
		{17, "target.md"},
		{18, "https://img.example.com/b.svg"},
		{18, "https://ci.example.com"},
		{19, "a_b.md"},
		{19, "x.md?a=1&b=2"},
		{23, "#title"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("extractLinks mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestBlankCodeSpans(t *testing.T) {
	cases := map[string]string{
		"a `b` c":          "a     c",
		"a ``x ` y`` c":    "a " + spaces(9) + " c",
		"unclosed `tick":   "unclosed `tick",
		"`one` and `two`!": spaces(5) + " and " + spaces(5) + "!",
	}
	for in, want := range cases {
		if got := blankCodeSpans(in); got != want {
			t.Errorf("blankCodeSpans(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		kind linkKind
		req  string
	}{
		{"https://example.com/a#frag", kindExternal, "https://example.com/a"},
		{"HTTP://Example.com", kindExternal, "http://Example.com"},
		{"//cdn.example.com/x.js", kindExternal, "https://cdn.example.com/x.js"},
		{"mailto:me@example.com", kindSkip, ""},
		{"tel:+123", kindSkip, ""},
		{"docs/a.md#b", kindInternal, ""},
		{"#local", kindInternal, ""},
		{"/abs/path.md", kindInternal, ""},
		{"http://", kindInvalid, ""},
		{"%zz", kindInvalid, ""},
	}
	for _, c := range cases {
		kind, req := classify(c.in)
		if kind != c.kind || req != c.req {
			t.Errorf("classify(%q) = %v, %q; want %v, %q", c.in, kind, req, c.kind, c.req)
		}
	}
}

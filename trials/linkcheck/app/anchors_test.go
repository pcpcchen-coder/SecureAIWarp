package main

import "testing"

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Hello World":                  "hello-world",
		"Getting Started!":             "getting-started",
		"API v2.0 (beta)":              "api-v20-beta",
		"`code` and [link](x.md)":      "code-and-link",
		"安裝與設定":                        "安裝與設定",
		"Step 1: 安裝 Go":                "step-1-安裝-go",
		"snake_case & kebab-case":      "snake_case--kebab-case",
		"  Trimmed  ":                  "trimmed",
		"Émoji 🚀 rocket":               "émoji--rocket",
		"<span>HTML</span> in heading": "html-in-heading",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectAnchors(t *testing.T) {
	src := "# Intro\n" +
		"## Usage ##\n" +
		"## Usage\n" +
		"## Usage\n" +
		"Setext Title\n" +
		"============\n" +
		"Sub Title\n" +
		"---------\n" +
		"### Custom {#my-id}\n" +
		"<a name=\"legacy\"></a>\n" +
		"<div id='box'></div>\n" +
		"```\n" +
		"# not a heading\n" +
		"```\n" +
		"#hashtag is not a heading\n" +
		"- list item\n" +
		"---\n"

	got := collectAnchors(src)
	for _, a := range []string{"intro", "usage", "usage-1", "usage-2", "setext-title", "sub-title", "my-id", "custom", "legacy", "box"} {
		if !got[a] {
			t.Errorf("missing anchor %q (got %v)", a, got)
		}
	}
	for _, a := range []string{"not-a-heading", "hashtag-is-not-a-heading", "list-item"} {
		if got[a] {
			t.Errorf("unexpected anchor %q", a)
		}
	}
}

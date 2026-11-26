package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Options configures a link check run.
type Options struct {
	Dir          string           // directory to scan
	Root         string           // directory that site-absolute links ("/x.md") resolve against; defaults to Dir
	Extensions   []string         // Markdown file extensions, e.g. ".md"
	Concurrency  int              // number of concurrent external requests
	Timeout      time.Duration    // per-request timeout
	Retries      int              // retries for network errors, 429 and 5xx
	RetryDelay   time.Duration    // base delay between retries
	SkipExternal bool             // do not check http(s) links
	Exclude      []*regexp.Regexp // links matching any of these are skipped
	AcceptStatus map[int]bool     // extra HTTP status codes treated as OK
	UserAgent    string
	Client       *http.Client // optional; built from Timeout when nil
}

// Occurrence is one place a link appears.
type Occurrence struct {
	File string // path relative to Dir, with forward slashes
	Line int
	URL  string
}

// Problem is a broken link.
type Problem struct {
	Occurrence
	Reason string
}

// Report is the outcome of a run.
type Report struct {
	Files    int
	Links    int
	Internal int
	External int // occurrences of external links
	Unique   int // unique external URLs requested
	Skipped  int
	Problems []Problem
}

type checker struct {
	opts    Options
	client  *http.Client
	mu      sync.Mutex
	anchors map[string]map[string]bool // absolute file path -> anchors
}

// Run scans opts.Dir and checks every link it finds.
func Run(ctx context.Context, opts Options) (*Report, error) {
	if opts.Dir == "" {
		opts.Dir = "."
	}
	dir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", opts.Dir)
	}
	opts.Dir = dir
	if opts.Root == "" {
		opts.Root = dir
	} else if opts.Root, err = filepath.Abs(opts.Root); err != nil {
		return nil, err
	}
	if len(opts.Extensions) == 0 {
		opts.Extensions = []string{".md", ".markdown"}
	}
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "linkcheck/1.0 (+markdown link checker)"
	}
	c := &checker{opts: opts, client: opts.Client, anchors: map[string]map[string]bool{}}
	if c.client == nil {
		c.client = &http.Client{Timeout: opts.Timeout}
	}

	files, err := c.findFiles()
	if err != nil {
		return nil, err
	}
	rep := &Report{Files: len(files)}
	external := map[string][]Occurrence{} // request URL -> occurrences

	for _, abs := range files {
		data, err := os.ReadFile(abs)
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(dir, abs)
		rel = filepath.ToSlash(rel)
		for _, l := range extractLinks(string(data)) {
			rep.Links++
			occ := Occurrence{File: rel, Line: l.Line, URL: l.URL}
			if c.excluded(l.URL) {
				rep.Skipped++
				continue
			}
			kind, target := classify(l.URL)
			switch kind {
			case kindSkip:
				rep.Skipped++
			case kindInvalid:
				rep.Problems = append(rep.Problems, Problem{occ, "invalid URL"})
			case kindExternal:
				rep.External++
				if opts.SkipExternal {
					continue
				}
				external[target] = append(external[target], occ)
			case kindInternal:
				rep.Internal++
				if reason := c.checkInternal(abs, l.URL); reason != "" {
					rep.Problems = append(rep.Problems, Problem{occ, reason})
				}
			}
		}
	}

	rep.Unique = len(external)
	for u, reason := range c.checkExternal(ctx, external) {
		for _, occ := range external[u] {
			rep.Problems = append(rep.Problems, Problem{occ, reason})
		}
	}
	sort.Slice(rep.Problems, func(i, j int) bool {
		a, b := rep.Problems[i], rep.Problems[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.URL < b.URL
	})
	return rep, ctx.Err()
}

func (c *checker) isMarkdown(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, e := range c.opts.Extensions {
		if ext == strings.ToLower(e) {
			return true
		}
	}
	return false
}

func (c *checker) findFiles() ([]string, error) {
	var files []string
	err := filepath.WalkDir(c.opts.Dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != c.opts.Dir && (strings.HasPrefix(name, ".") || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if c.isMarkdown(path) {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func (c *checker) excluded(link string) bool {
	for _, re := range c.opts.Exclude {
		if re.MatchString(link) {
			return true
		}
	}
	return false
}

type linkKind int

const (
	kindInternal linkKind = iota
	kindExternal
	kindSkip
	kindInvalid
)

// classify decides how a link is checked. For external links it also returns
// the URL to request (without fragment).
func classify(link string) (linkKind, string) {
	if strings.HasPrefix(link, "//") {
		link = "https:" + link
	}
	u, err := url.Parse(link)
	if err != nil {
		return kindInvalid, ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		if u.Host == "" {
			return kindInvalid, ""
		}
		u.Fragment = ""
		u.RawFragment = ""
		return kindExternal, u.String()
	case "":
		return kindInternal, ""
	default: // mailto:, tel:, ftp:, data:, javascript: ...
		return kindSkip, ""
	}
}

// checkInternal checks a relative or site-absolute link from file src.
// It returns "" when the link is fine, or a reason otherwise.
func (c *checker) checkInternal(src, link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return "invalid URL"
	}
	fragment := u.Fragment // already percent-decoded
	target := src
	if u.Path != "" {
		p := filepath.FromSlash(u.Path)
		if strings.HasPrefix(u.Path, "/") {
			p = filepath.Join(c.opts.Root, p)
		} else {
			p = filepath.Join(filepath.Dir(src), p)
		}
		resolved, ok := c.resolveFile(p)
		if !ok {
			return "file not found"
		}
		target = resolved
	}
	if fragment == "" || !c.isMarkdown(target) {
		return ""
	}
	if st, err := os.Stat(target); err == nil && st.IsDir() {
		return ""
	}
	anchors, err := c.anchorsOf(target)
	if err != nil {
		return "cannot read target: " + err.Error()
	}
	if anchors[fragment] {
		return ""
	}
	lower := strings.ToLower(fragment)
	for a := range anchors {
		if strings.ToLower(a) == lower {
			return ""
		}
	}
	return fmt.Sprintf("anchor #%s not found", fragment)
}

// resolveFile finds the file a link path refers to, allowing the shortcuts
// static-site generators use: "page" -> "page.md", "page.html" -> "page.md",
// and "dir/" -> "dir/index.md" or "dir/README.md".
func (c *checker) resolveFile(p string) (string, bool) {
	if st, err := os.Stat(p); err == nil {
		if !st.IsDir() {
			return p, true
		}
		for _, idx := range []string{"index.md", "README.md", "readme.md", "_index.md"} {
			cand := filepath.Join(p, idx)
			if fileExists(cand) {
				return cand, true
			}
		}
		return p, true // a directory is a valid target on its own
	}
	ext := strings.ToLower(filepath.Ext(p))
	base := p
	if ext == ".html" || ext == ".htm" {
		base = strings.TrimSuffix(p, filepath.Ext(p))
	} else if ext != "" {
		return "", false
	}
	for _, e := range c.opts.Extensions {
		if fileExists(base + e) {
			return base + e, true
		}
	}
	return "", false
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func (c *checker) anchorsOf(path string) (map[string]bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if a, ok := c.anchors[path]; ok {
		return a, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	a := collectAnchors(string(data))
	c.anchors[path] = a
	return a, nil
}

// checkExternal requests every URL with a bounded worker pool and returns
// the reason for each URL that failed.
func (c *checker) checkExternal(ctx context.Context, urls map[string][]Occurrence) map[string]string {
	jobs := make(chan string)
	failed := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < c.opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				if reason := c.checkURL(ctx, u); reason != "" {
					mu.Lock()
					failed[u] = reason
					mu.Unlock()
				}
			}
		}()
	}
	keys := make([]string, 0, len(urls))
	for u := range urls {
		keys = append(keys, u)
	}
	sort.Strings(keys)
feed:
	for _, u := range keys {
		select {
		case jobs <- u:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return failed
}

func (c *checker) statusOK(code int) bool {
	return (code >= 200 && code < 400) || c.opts.AcceptStatus[code]
}

// checkURL returns "" if the URL is reachable, or a reason otherwise.
// It tries HEAD first and falls back to GET, since many servers reject HEAD.
func (c *checker) checkURL(ctx context.Context, u string) string {
	var reason string
	for attempt := 0; attempt <= c.opts.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(c.opts.RetryDelay * time.Duration(attempt)):
			case <-ctx.Done():
				return "canceled"
			}
		}
		code, err := c.request(ctx, http.MethodHead, u)
		if err == nil && c.statusOK(code) {
			return ""
		}
		if err == nil { // HEAD gave an error status: confirm with GET
			code, err = c.request(ctx, http.MethodGet, u)
			if err == nil && c.statusOK(code) {
				return ""
			}
		}
		if err != nil {
			reason = "request failed: " + describeErr(err)
		} else {
			reason = fmt.Sprintf("HTTP %d %s", code, http.StatusText(code))
			if code != http.StatusTooManyRequests && code < 500 {
				return reason // definitive client error, do not retry
			}
		}
	}
	return reason
}

func (c *checker) request(ctx context.Context, method, u string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", c.opts.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 64<<10)
	return resp.StatusCode, nil
}

func describeErr(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		if uerr.Timeout() {
			return "timeout"
		}
		return uerr.Err.Error()
	}
	return err.Error()
}

// Command linkcheck scans a directory of Markdown files and reports broken
// links: missing files and anchors for internal links, and failing HTTP
// status codes for external links. It exits with status 1 when any link is
// broken, so it can be used in CI.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	exitOK     = 0
	exitBroken = 1
	exitUsage  = 2
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("linkcheck", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var (
		opts     Options
		excludes multiFlag
		accept   string
		exts     string
		format   string
		quiet    bool
	)
	fl.StringVar(&opts.Root, "root", "", "directory that site-absolute links like /guide/x.md resolve against (default: the scanned directory)")
	fl.IntVar(&opts.Concurrency, "concurrency", 16, "number of external links checked at the same time")
	fl.DurationVar(&opts.Timeout, "timeout", 15*time.Second, "timeout for each HTTP request")
	fl.IntVar(&opts.Retries, "retries", 2, "retries for network errors, HTTP 429 and 5xx")
	fl.DurationVar(&opts.RetryDelay, "retry-delay", time.Second, "base delay between retries (multiplied by the attempt number)")
	fl.BoolVar(&opts.SkipExternal, "offline", false, "skip external (http/https) links; only check internal links")
	fl.Var(&excludes, "exclude", "regular expression; links matching it are skipped (repeatable)")
	fl.StringVar(&accept, "accept", "", "comma-separated extra HTTP status codes to treat as OK, e.g. 403,429")
	fl.StringVar(&exts, "ext", ".md,.markdown", "comma-separated Markdown file extensions to scan")
	fl.StringVar(&format, "format", "text", "output format: text or json")
	fl.BoolVar(&quiet, "quiet", false, "do not print the summary line")
	fl.Usage = func() {
		fmt.Fprintf(stderr, "Usage: linkcheck [flags] [directory]\n\nChecks every link in the Markdown files under directory (default \".\").\nExit status: 0 = all links OK, 1 = broken links found, 2 = usage or runtime error.\n\nFlags:\n")
		fl.PrintDefaults()
	}
	if err := fl.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return exitOK
		}
		return exitUsage
	}
	if fl.NArg() > 1 {
		fmt.Fprintln(stderr, "linkcheck: expected at most one directory argument")
		fl.Usage()
		return exitUsage
	}
	opts.Dir = "."
	if fl.NArg() == 1 {
		opts.Dir = fl.Arg(0)
	}
	if format != "text" && format != "json" {
		fmt.Fprintf(stderr, "linkcheck: unknown -format %q (want text or json)\n", format)
		return exitUsage
	}
	for _, e := range excludes {
		re, err := regexp.Compile(e)
		if err != nil {
			fmt.Fprintf(stderr, "linkcheck: bad -exclude %q: %v\n", e, err)
			return exitUsage
		}
		opts.Exclude = append(opts.Exclude, re)
	}
	if accept != "" {
		opts.AcceptStatus = map[int]bool{}
		for _, s := range strings.Split(accept, ",") {
			code, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || code < 100 || code > 999 {
				fmt.Fprintf(stderr, "linkcheck: bad -accept status code %q\n", s)
				return exitUsage
			}
			opts.AcceptStatus[code] = true
		}
	}
	for _, e := range strings.Split(exts, ",") {
		if e = strings.TrimSpace(e); e != "" {
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			opts.Extensions = append(opts.Extensions, e)
		}
	}

	rep, err := Run(ctx, opts)
	if err != nil {
		fmt.Fprintf(stderr, "linkcheck: %v\n", err)
		return exitUsage
	}

	if format == "json" {
		type item struct {
			File   string `json:"file"`
			Line   int    `json:"line"`
			URL    string `json:"url"`
			Reason string `json:"reason"`
		}
		out := struct {
			Files    int    `json:"files"`
			Links    int    `json:"links"`
			Broken   []item `json:"broken"`
			Internal int    `json:"internal"`
			External int    `json:"external"`
			Skipped  int    `json:"skipped"`
		}{rep.Files, rep.Links, []item{}, rep.Internal, rep.External, rep.Skipped}
		for _, p := range rep.Problems {
			out.Broken = append(out.Broken, item{p.File, p.Line, p.URL, p.Reason})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		for _, p := range rep.Problems {
			fmt.Fprintf(stdout, "%s:%d: %s (%s)\n", p.File, p.Line, p.URL, p.Reason)
		}
		if !quiet {
			ext := fmt.Sprintf("%d external (%d unique URLs)", rep.External, rep.Unique)
			if opts.SkipExternal {
				ext = fmt.Sprintf("%d external (not checked, -offline)", rep.External)
			}
			fmt.Fprintf(stderr, "linkcheck: %d files, %d links: %d internal, %s, %d skipped; %d broken\n",
				rep.Files, rep.Links, rep.Internal, ext, rep.Skipped, len(rep.Problems))
		}
	}
	if len(rep.Problems) > 0 {
		return exitBroken
	}
	return exitOK
}

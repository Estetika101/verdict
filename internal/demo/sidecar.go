package demo

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/Estetika101/verdict/internal/model"
)

// Sidecar fetches: the only URLs besides the scanned page itself that the
// public demo will ever request. They exist because the GEO module's most
// useful facts — which AI crawlers robots.txt admits, what Content Signals it
// declares, whether an llms.txt exists — live in fixed, well-known files, not
// in the page. The policy is deliberately narrow, and every limb of it is
// enforced here rather than trusted to the checks that ask:
//
//   - same origin as the page's FINAL URL (scheme, host and port), so a check
//     can't be steered at another host, and the origin is one safeFetch has
//     already validated;
//   - one of three fixed paths, no query, no fragment, no userinfo;
//   - at most maxSidecarFetches network requests per scan, with repeats of
//     the same URL served from a per-scan cache (bot posture and Content
//     Signals both read robots.txt; it's fetched once);
//   - through safeFetchLimit, so every request — and every redirect hop — gets
//     the same dial-time SSRF guard as the page, with a smaller body cap
//     (Google caps robots.txt at 500 KiB; this matches it) and a shorter
//     timeout.
//
// Anything else gets errSidecarNotAllowed, which checks report as skipped.
var sidecarPaths = map[string]bool{
	"/robots.txt":    true,
	"/llms.txt":      true,
	"/llms-full.txt": true,
}

// sidecarChecks are the site-scoped checks the demo runs, by ID. An explicit
// list, unlike the page-scope filter: a site-scoped check is only safe here if
// every URL it fetches is inside sidecarPaths, and that's a property of the
// check's code, not of its declared scope. (A check that asked for anything
// else would just be refused at Fetch — but it would then show the visitor a
// skipped line for no reason, so it doesn't belong on the list.)
var sidecarChecks = map[string]bool{
	"geo-bot-posture":     true,
	"geo-llms-txt":        true,
	"geo-content-signals": true,
}

const (
	maxSidecarFetches = 3
	maxSidecarBytes   = 500 << 10
	sidecarTimeout    = 5 * time.Second
)

var errSidecarNotAllowed = errors.New("demo: only /robots.txt, /llms.txt and /llms-full.txt on the scanned origin can be fetched")

// FetchEvent is one network request a scan made. The list goes back to the
// visitor as the scan log, so it carries only what they'd see anyway: what was
// fetched, the status, the size and how long it took — or a user-facing
// error, never raw internals.
type FetchEvent struct {
	What   string `json:"what"` // "page", or the sidecar path
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
	Ms     int64  `json:"ms"`
	Err    string `json:"error,omitempty"`
}

type sidecarResult struct {
	pd  model.PageData
	err error
}

// demoCheckContext wraps the one fetched page plus the sidecar policy above.
// Checks run sequentially within a scan, so it needs no locking.
type demoCheckContext struct {
	ctx    context.Context // the scan's context: its deadline bounds every sidecar fetch
	page   model.PageData
	origin string // scheme://host[:port] of the page's final URL; "" disables sidecars
	cache  map[string]sidecarResult
	used   int
	trace  []FetchEvent
}

func newDemoCheckContext(ctx context.Context, page model.PageData) *demoCheckContext {
	c := &demoCheckContext{ctx: ctx, page: page, cache: map[string]sidecarResult{}}
	if u, err := url.Parse(page.FinalURL); err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") {
		c.origin = u.Scheme + "://" + u.Host
	}
	return c
}

func (c *demoCheckContext) Scope() model.Scope   { return model.ScopePage }
func (c *demoCheckContext) Page() model.PageData { return c.page }

// Corpus is just the page: site-scoped checks use it only to find the origin.
func (c *demoCheckContext) Corpus() []model.PageData { return []model.PageData{c.page} }
func (c *demoCheckContext) Config() model.CheckConfig {
	return model.CheckConfig{WCAGVersion: "2.2", WCAGLevel: "AA"}
}
func (c *demoCheckContext) Logf(string, ...any) {}

// Fetch ignores the caller's context on purpose: checks pass
// context.Background(), and a sidecar must never outlive the scan's deadline.
func (c *demoCheckContext) Fetch(_ context.Context, rawURL string) (model.PageData, error) {
	if r, ok := c.cache[rawURL]; ok {
		return r.pd, r.err
	}
	u, err := url.Parse(rawURL)
	if err != nil || c.origin == "" || u.Scheme+"://"+u.Host != c.origin ||
		!sidecarPaths[u.Path] || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return model.PageData{}, errSidecarNotAllowed
	}
	if c.used >= maxSidecarFetches {
		return model.PageData{}, model.ErrBudgetExhausted
	}
	c.used++

	fctx, cancel := context.WithTimeout(c.ctx, sidecarTimeout)
	defer cancel()
	start := time.Now()
	pd, err := safeFetchLimit(fctx, rawURL, maxSidecarBytes)
	ev := FetchEvent{What: u.Path, URL: rawURL, Ms: time.Since(start).Milliseconds()}
	if err != nil {
		ev.Err = userFacingError(err)
	} else {
		ev.Status, ev.Bytes = pd.Status, len(pd.Body)
	}
	c.trace = append(c.trace, ev)
	c.cache[rawURL] = sidecarResult{pd, err}
	return pd, err
}

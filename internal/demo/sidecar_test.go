package demo

import (
	"context"
	"errors"
	"testing"

	"github.com/Estetika101/verdict/internal/model"
)

func sidecarCtx() *demoCheckContext {
	return newDemoCheckContext(context.Background(), model.PageData{FinalURL: "https://site.example/blog/post?x=1"})
}

// Everything outside the policy is refused before any network call — these
// URLs would otherwise resolve (or fail to) for real, so a nil error or a
// non-policy error here would mean the guard let something through.
func TestSidecarFetch_RefusesOutsidePolicy(t *testing.T) {
	for name, u := range map[string]string{
		"other host":       "https://evil.example/robots.txt",
		"subdomain":        "https://www.site.example/robots.txt",
		"other scheme":     "http://site.example/robots.txt",
		"other port":       "https://site.example:8443/robots.txt",
		"other path":       "https://site.example/sitemap.xml",
		"page itself":      "https://site.example/blog/post",
		"query":            "https://site.example/robots.txt?a=1",
		"fragment":         "https://site.example/llms.txt#x",
		"userinfo":         "https://user@site.example/robots.txt",
		"path traversal":   "https://site.example/x/../robots.txt",
		"case-varied path": "https://site.example/ROBOTS.TXT",
		"unparseable":      "https://site.example/%zz",
	} {
		if _, err := sidecarCtx().Fetch(context.Background(), u); !errors.Is(err, errSidecarNotAllowed) {
			t.Errorf("%s (%s): err = %v, want errSidecarNotAllowed", name, u, err)
		}
	}
}

func TestSidecarFetch_NoOriginNoFetch(t *testing.T) {
	c := newDemoCheckContext(context.Background(), model.PageData{FinalURL: ""})
	if _, err := c.Fetch(context.Background(), "https://site.example/robots.txt"); !errors.Is(err, errSidecarNotAllowed) {
		t.Errorf("err = %v, want errSidecarNotAllowed", err)
	}
}

func TestSidecarFetch_BudgetAndCache(t *testing.T) {
	c := sidecarCtx()
	cached := model.PageData{Status: 200, Body: []byte("User-agent: *\nAllow: /\n")}
	c.cache["https://site.example/robots.txt"] = sidecarResult{pd: cached}
	c.used = maxSidecarFetches

	// A cached URL is served even with the budget spent: repeats are free.
	pd, err := c.Fetch(context.Background(), "https://site.example/robots.txt")
	if err != nil || string(pd.Body) != string(cached.Body) {
		t.Fatalf("cached fetch = (%q, %v), want the cached body", pd.Body, err)
	}
	// A new allowed URL past the budget is refused without a request.
	if _, err := c.Fetch(context.Background(), "https://site.example/llms.txt"); !errors.Is(err, model.ErrBudgetExhausted) {
		t.Errorf("err = %v, want ErrBudgetExhausted", err)
	}
	if len(c.trace) != 0 {
		t.Errorf("trace = %v, want no network events", c.trace)
	}
}

// The demo's check list is every page-scoped check plus exactly the named
// sidecar checks — never a site check that could fetch arbitrary URLs.
func TestNewServer_CheckSelection(t *testing.T) {
	s, err := NewServer(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range s.checks {
		m := c.Meta()
		if m.Scope != model.ScopePage && !sidecarChecks[m.ID] {
			t.Errorf("site-scoped check %q is running in the demo", m.ID)
		}
		if m.ID == "broken-links" || m.Module == "links" {
			t.Errorf("link checking must never run in the demo: %q", m.ID)
		}
	}
}

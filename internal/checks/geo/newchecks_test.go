package geo_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Estetika101/verdict/internal/checks/geo"
	"github.com/Estetika101/verdict/internal/model"
)

func pageWithHeaders(t *testing.T, html string, hdr map[string][]string) model.PageData {
	t.Helper()
	p := pageFromHTML(t, "https://x.example/", html)
	p.Headers = http.Header{}
	for k, vs := range hdr {
		for _, v := range vs {
			p.Headers.Add(k, v)
		}
	}
	return p
}

// --- SnippetControls ---

func TestSnippetControls(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		hdr      map[string][]string
		status   model.Status
		severity model.Severity
		contains []string
		absent   []string
	}{
		{name: "nothing restrictive", html: `<body><p>hi</p></body>`, status: model.StatusPass},
		{name: "meta robots nosnippet", html: `<meta name="robots" content="index, NoSnippet">`, status: model.StatusInfo,
			contains: []string{"nosnippet in effect (meta robots)", "AI Overviews or AI Mode"}},
		{name: "meta name case-insensitive", html: `<meta name="ROBOTS" content="nosnippet">`, status: model.StatusInfo,
			contains: []string{"nosnippet in effect"}},
		{name: "googlebot meta nosnippet", html: `<meta name="googlebot" content="nosnippet">`, status: model.StatusInfo,
			contains: []string{"meta googlebot"}},
		{name: "max-snippet 0 equals nosnippet", html: `<meta name="robots" content="max-snippet:0">`, status: model.StatusInfo,
			contains: []string{"nosnippet in effect"}},
		{name: "max-snippet N", html: `<meta name="robots" content="max-snippet:160">`, status: model.StatusInfo,
			contains: []string{"max-snippet:160", "at most 160 characters", "AI Overviews and AI Mode"}},
		{name: "max-snippet -1 is no limit", html: `<meta name="robots" content="max-snippet:-1">`, status: model.StatusPass},
		{name: "more restrictive wins", html: `<meta name="robots" content="max-snippet:160"><meta name="googlebot" content="max-snippet:50">`,
			status: model.StatusInfo, contains: []string{"max-snippet:50"}, absent: []string{"max-snippet:160"}},
		{name: "nosnippet beats max-snippet", html: `<meta name="robots" content="max-snippet:50, nosnippet">`,
			status: model.StatusInfo, contains: []string{"nosnippet in effect"}},
		{name: "header nosnippet", html: `<body></body>`, hdr: map[string][]string{"X-Robots-Tag": {"nosnippet"}},
			status: model.StatusInfo, contains: []string{"nosnippet in effect (X-Robots-Tag)"}},
		{name: "header googlebot-scoped applies", html: `<body></body>`, hdr: map[string][]string{"x-robots-tag": {"Googlebot: nosnippet"}},
			status: model.StatusInfo, contains: []string{"nosnippet in effect"}},
		{name: "header other-bot-scoped ignored", html: `<body></body>`, hdr: map[string][]string{"X-Robots-Tag": {"bingbot: nosnippet"}},
			status: model.StatusPass},
		{name: "header unscoped max-snippet with colon is not a UA prefix", html: `<body></body>`, hdr: map[string][]string{"X-Robots-Tag": {"max-snippet:20"}},
			status: model.StatusInfo, contains: []string{"max-snippet:20"}},
		{name: "meta and header combine", html: `<meta name="robots" content="max-snippet:200">`, hdr: map[string][]string{"X-Robots-Tag": {"max-snippet:80"}},
			status: model.StatusInfo, contains: []string{"max-snippet:80", "X-Robots-Tag"}},
		{name: "valid data-nosnippet alone", html: `<body><span data-nosnippet>a</span><div data-nosnippet>b</div><section data-nosnippet>c</section></body>`,
			status: model.StatusPass, contains: []string{"3 valid data-nosnippet"}},
		{name: "data-nosnippet on p fails", html: `<body><p data-nosnippet>a</p><li data-nosnippet>b</li><span data-nosnippet>c</span></body>`,
			status: model.StatusFail, severity: model.SeverityWarn,
			contains: []string{"2 element(s) outside span, div, section", "<li>", "<p>", "1 valid data-nosnippet"}},
		{name: "noai note", html: `<meta name="robots" content="noai, noimageai">`, status: model.StatusInfo,
			contains: []string{"not recognised by Google"}},
		{name: "noindex noted not failed", html: `<meta name="robots" content="noindex">`, status: model.StatusPass,
			contains: []string{"also noindex", "see SEO"}},
		{name: "none noted", html: `<meta name="robots" content="none, nosnippet">`, status: model.StatusInfo,
			contains: []string{"nosnippet in effect", "also noindex"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := onlyFinding(t, runPage(t, geo.SnippetControls(), pageWithHeaders(t, tc.html, tc.hdr)))
			if f.Status != tc.status || f.Severity != tc.severity {
				t.Fatalf("got %s/%s, want %s/%s: %+v", f.Status, f.Severity, tc.status, tc.severity, f)
			}
			for _, c := range tc.contains {
				if !strings.Contains(f.Observed, c) {
					t.Errorf("observed %q missing %q", f.Observed, c)
				}
			}
			for _, c := range tc.absent {
				if strings.Contains(f.Observed, c) {
					t.Errorf("observed %q should not contain %q", f.Observed, c)
				}
			}
			if f.Status == model.StatusFail && (f.Required == "" || f.SuggestedFix == "") {
				t.Errorf("fail needs Required and SuggestedFix: %+v", f)
			}
			if f.Criterion != "geo-snippet-controls" || f.Module != "geo" {
				t.Errorf("bad identity: %+v", f)
			}
		})
	}
}

// --- StructuredData ---

func TestStructuredData(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		status   model.Status
		contains []string
	}{
		{name: "none", html: `<body></body>`, status: model.StatusInfo, contains: []string{"no JSON-LD", "no special schema"}},
		{name: "valid with types", status: model.StatusPass,
			html:     `<script type="application/ld+json">{"@context":"https://schema.org","@type":"Article","author":{"@type":"Person","name":"A"}}</script>`,
			contains: []string{"1 JSON-LD block(s) parse", "Article", "Person"}},
		{name: "graph and type arrays, type with params and case", status: model.StatusPass,
			html:     `<script type="Application/LD+JSON; charset=utf-8">{"@context":"https://schema.org","@graph":[{"@type":["Organization","Brand"]},{"@type":"WebSite"}]}</script>`,
			contains: []string{"Organization", "Brand", "WebSite"}},
		{name: "top-level array", status: model.StatusPass,
			html:     `<script type="application/ld+json">[{"@context":"https://schema.org","@type":"A"},{"@context":"https://schema.org","@type":"B"}]</script>`,
			contains: []string{"A, B"}},
		{name: "invalid json", status: model.StatusFail,
			html: `<script type="application/ld+json">{"@context":"https://schema.org",}</script>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Thing"}</script>`,
			contains: []string{"1 of 2 JSON-LD blocks don't parse", "engines ignore invalid markup", "first error", "Thing"}},
		{name: "missing context", status: model.StatusFail,
			html:     `<script type="application/ld+json">{"@type":"Article"}</script>`,
			contains: []string{"without @context", "Article"}},
		{name: "graph root without context", status: model.StatusFail,
			html:     `<script type="application/ld+json">{"@graph":[{"@type":"WebSite"}]}</script>`,
			contains: []string{"without @context"}},
		{name: "other script types ignored", status: model.StatusInfo,
			html: `<script type="application/json">{not json</script><script>var x</script>`, contains: []string{"no JSON-LD"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := onlyFinding(t, runPage(t, geo.StructuredData(), pageFromHTML(t, "https://x/", tc.html)))
			if f.Status != tc.status {
				t.Fatalf("status = %s, want %s: %+v", f.Status, tc.status, f)
			}
			if f.Status == model.StatusFail && (f.Severity != model.SeverityWarn || f.Required == "" || f.SuggestedFix == "") {
				t.Errorf("fail must be warn with Required/SuggestedFix: %+v", f)
			}
			for _, c := range tc.contains {
				if !strings.Contains(f.Observed, c) {
					t.Errorf("observed %q missing %q", f.Observed, c)
				}
			}
			if len(f.Observed) > 300 {
				t.Errorf("observed too long (%d)", len(f.Observed))
			}
		})
	}
}

// --- ServerRenderedText ---

func TestServerRenderedText(t *testing.T) {
	long := strings.Repeat("word ", 60)
	tests := []struct {
		name     string
		html     string
		status   model.Status
		contains []string
	}{
		{name: "empty root shell", status: model.StatusFail,
			html:     `<html><body><div id="root"></div><script>window.x=1;var a="lots of words in script that must not count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count count"</script></body></html>`,
			contains: []string{"0 words in the server HTML", "empty #root app shell", "GPTBot, ClaudeBot, PerplexityBot"}},
		{name: "whitespace-only next shell", status: model.StatusFail,
			html: "<body><div id=\"__next\">  \n </div></body>", contains: []string{"empty #__next app shell"}},
		{name: "few words no shell", status: model.StatusFail,
			html: `<body><p>Just a few words here.</p></body>`, contains: []string{"5 words in the server HTML"}},
		{name: "enough words", status: model.StatusPass,
			html: `<body><div id="root"><p>` + long + `</p></div></body>`, contains: []string{"60 words in the server HTML"}},
		{name: "exactly 50", status: model.StatusPass,
			html: `<body><p>` + strings.Repeat("a ", 50) + `</p></body>`, contains: []string{"50 words"}},
		{name: "excluded elements", status: model.StatusFail,
			html: `<body><noscript>` + long + `</noscript><template>` + long + `</template><svg><text>` + long + `</text></svg>` +
				`<style>` + long + `</style><div hidden>` + long + `</div><p>visible text</p></body>`,
			contains: []string{"2 words in the server HTML"}},
		{name: "adjacent blocks are separate words and punctuation is not a word", status: model.StatusFail,
			html: `<body><p>one</p><p>two</p><b>thr</b>ee <i>,</i> -</body>`, contains: []string{"3 words"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := onlyFinding(t, runPage(t, geo.ServerRenderedText(), pageFromHTML(t, "https://x/", tc.html)))
			if f.Status != tc.status {
				t.Fatalf("status = %s, want %s: %+v", f.Status, tc.status, f)
			}
			if f.Status == model.StatusFail && (f.Severity != model.SeverityWarn || f.Required == "" || f.SuggestedFix == "") {
				t.Errorf("fail must be warn with Required/SuggestedFix: %+v", f)
			}
			for _, c := range tc.contains {
				if !strings.Contains(f.Observed, c) {
					t.Errorf("observed %q missing %q", f.Observed, c)
				}
			}
		})
	}
}

// --- ContentSignals ---

func robotsCtx(body string, status int, err error) *stubCtx {
	seed := model.PageData{FinalURL: "https://x.example/"}
	return &stubCtx{
		corpus: []model.PageData{seed},
		fetch: func(_ context.Context, url string) (model.PageData, error) {
			if !strings.HasSuffix(url, "/robots.txt") {
				panic("unexpected fetch " + url)
			}
			return model.PageData{Status: status, Body: []byte(body)}, err
		},
	}
}

func TestContentSignals(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		status   int
		err      error
		want     model.Status
		contains []string
		reason   string
	}{
		{name: "no robots.txt", status: 404, want: model.StatusInfo, contains: []string{"no Content-Signal declared", "neither grants nor restricts"}},
		{name: "robots without signals", status: 200, body: "User-agent: *\nDisallow: /private\n", want: model.StatusInfo,
			contains: []string{"no Content-Signal declared"}},
		{name: "cloudflare example", status: 200, body: "User-Agent: *\nContent-Signal: search=yes, ai-train=no\nAllow: /\n", want: model.StatusInfo,
			contains: []string{"* — search=yes, ai-train=no (ai-input: not declared)"}},
		{name: "field name case-insensitive and all three", status: 200, body: "user-agent: *\nCONTENT-SIGNAL: search=yes, ai-input=no, ai-train=no # c\n", want: model.StatusInfo,
			contains: []string{"* — search=yes, ai-input=no, ai-train=no"}},
		{name: "per group attribution", status: 200,
			body:     "User-agent: *\nContent-Signal: search=yes\n\nUser-agent: GPTBot\nUser-agent: ClaudeBot\nDisallow: /x\nContent-Signal: ai-train=no\n",
			want:     model.StatusInfo,
			contains: []string{"* — search=yes (ai-input, ai-train: not declared)", "GPTBot, ClaudeBot — ai-train=no (search, ai-input: not declared)"}},
		{name: "unknown key", status: 200, body: "User-agent: *\nContent-Signal: search=yes, ai-trian=no\n", want: model.StatusFail,
			contains: []string{`unknown signal "ai-trian"`}},
		{name: "bad value", status: 200, body: "User-agent: *\nContent-Signal: search=maybe\n", want: model.StatusFail,
			contains: []string{`search="maybe"`}},
		{name: "token without equals", status: 200, body: "User-agent: *\nContent-Signal: search\n", want: model.StatusFail,
			contains: []string{"is not name=value"}},
		{name: "budget", status: 0, err: model.ErrBudgetExhausted, want: model.StatusSkipped, reason: "fetch budget exhausted"},
		{name: "blocked", status: 0, err: model.ErrBlocked, want: model.StatusSkipped, reason: "blocked"},
		{name: "robots disallowed", status: 0, err: model.ErrRobotsDisallowed, want: model.StatusSkipped, reason: "disallowed by robots.txt"},
		{name: "network error is no robots.txt", status: 0, err: errors.New("boom"), want: model.StatusInfo, contains: []string{"no Content-Signal declared"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := onlyFinding(t, runSite(t, geo.ContentSignals(), robotsCtx(tc.body, tc.status, tc.err)))
			if f.Status != tc.want {
				t.Fatalf("status = %s, want %s: %+v", f.Status, tc.want, f)
			}
			if f.Status == model.StatusFail && (f.Severity != model.SeverityWarn || f.Required != "comma-separated search|ai-input|ai-train = yes|no") {
				t.Errorf("fail must be warn with the documented Required: %+v", f)
			}
			if f.Status == model.StatusSkipped && f.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", f.Reason, tc.reason)
			}
			for _, c := range tc.contains {
				if !strings.Contains(f.Observed, c) {
					t.Errorf("observed %q missing %q", f.Observed, c)
				}
			}
			if f.Location.URL != "https://x.example/robots.txt" || f.Scope != model.ScopeSite {
				t.Errorf("bad location/scope: %+v", f)
			}
		})
	}
}

func TestNewGEOChecksRegistered(t *testing.T) {
	have := map[string]bool{}
	for _, c := range geo.All() {
		have[c.Meta().ID] = true
	}
	for _, id := range []string{"geo-snippet-controls", "geo-structured-data", "geo-server-rendered-text", "geo-content-signals"} {
		if !have[id] {
			t.Errorf("%s not in geo.All()", id)
		}
	}
}

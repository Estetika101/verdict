package security

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Estetika101/verdict/internal/model"
	"github.com/PuerkitoBio/goquery"
)

// htmlPage builds an https page from an HTML snippet. extra header pairs are
// added as repeated headers (so several Set-Cookie lines work).
func htmlPage(t *testing.T, finalURL, html string, hdr ...string) model.PageData {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	for i := 0; i+1 < len(hdr); i += 2 {
		h.Add(hdr[i], hdr[i+1])
	}
	return model.PageData{RequestedURL: finalURL, FinalURL: finalURL, Headers: h, Doc: doc, Body: []byte(html)}
}

// runOne runs a check and returns its single finding.
func runOne(t *testing.T, c model.Check, p model.PageData) model.Finding {
	t.Helper()
	fs, err := c.Run(stubCtx{p})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Module != "security" || f.Scope != model.ScopePage || f.Criterion != c.Meta().ID {
		t.Errorf("bad identity fields: %+v", f)
	}
	if f.Status != model.StatusPass && f.Observed == "" && f.Status != model.StatusSkipped {
		t.Errorf("non-pass finding without Observed: %+v", f)
	}
	if f.Status == model.StatusFail && (f.Required == "" || f.SuggestedFix == "" || f.Severity == "") {
		t.Errorf("fail missing Required/SuggestedFix/Severity: %+v", f)
	}
	if f.Status != model.StatusFail && f.Severity != "" {
		t.Errorf("non-fail carries severity: %+v", f)
	}
	if len(f.Observed) > 320 {
		t.Errorf("Observed too long (%d)", len(f.Observed))
	}
	return f
}

func want(t *testing.T, f model.Finding, st model.Status, sev model.Severity) {
	t.Helper()
	if f.Status != st || f.Severity != sev {
		t.Errorf("got %s/%s, want %s/%s (observed: %q)", f.Status, f.Severity, st, sev, f.Observed)
	}
}

func contains(t *testing.T, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("%q does not contain %q", s, sub)
		}
	}
}

func TestAll_OrderAndIDs(t *testing.T) {
	var ids []string
	for _, c := range All() {
		ids = append(ids, c.Meta().ID)
		if c.Meta().Module != "security" {
			t.Errorf("%s module = %s", c.Meta().ID, c.Meta().Module)
		}
	}
	got := strings.Join(ids, ",")
	wantIDs := "security-headers,security-https,security-cookies,security-mixed-content,security-version-disclosure,security-sri"
	if got != wantIDs {
		t.Errorf("All() = %s, want %s", got, wantIDs)
	}
}

func TestHTTPS(t *testing.T) {
	tests := []struct {
		name      string
		req, fin  string
		status    model.Status
		wantInObs string
	}{
		{"https", "https://example.test/", "https://example.test/", model.StatusPass, ""},
		{"http", "http://example.test/", "http://example.test/", model.StatusFail, "plain HTTP"},
		{"downgrade", "https://example.test/", "http://example.test/x", model.StatusFail, "redirected from HTTPS to HTTP"},
		{"upgrade redirect is fine", "http://example.test/", "https://example.test/", model.StatusPass, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := htmlPage(t, tc.fin, "<p>x</p>")
			p.RequestedURL = tc.req
			f := runOne(t, HTTPS(), p)
			if tc.status == model.StatusFail {
				want(t, f, model.StatusFail, model.SeverityError)
				contains(t, f.Observed, tc.wantInObs)
			} else {
				want(t, f, model.StatusPass, "")
			}
		})
	}
}

func TestCookies(t *testing.T) {
	const good = "id=SECRETVALUE; Secure; HttpOnly; SameSite=Lax; Path=/"
	tests := []struct {
		name    string
		url     string
		cookies []string
		status  model.Status
		sev     model.Severity
		obs     []string
	}{
		{"no cookies", "https://e.test/", nil, model.StatusPass, "", []string{"no cookies set on this response"}},
		{"all attributes", "https://e.test/", []string{good}, model.StatusPass, "", nil},
		{"attribute names case-insensitive", "https://e.test/", []string{"id=1; SECURE; httponly; samesite=strict"}, model.StatusPass, "", nil},
		{"missing Secure on https", "https://e.test/", []string{"a=1; HttpOnly; SameSite=Lax", good}, model.StatusFail, model.SeverityWarn, []string{"no Secure on HTTPS page: a"}},
		{"missing Secure on http page not flagged", "http://e.test/", []string{"a=1; HttpOnly; SameSite=Lax"}, model.StatusPass, "", nil},
		{"only HttpOnly/SameSite missing is info", "https://e.test/", []string{"theme=dark; Secure"}, model.StatusInfo, "", []string{"no HttpOnly: theme", "no SameSite (browsers default to Lax): theme"}},
		{"__Secure- without Secure", "https://e.test/", []string{"__Secure-sid=1; HttpOnly; SameSite=Lax"}, model.StatusFail, model.SeverityError, []string{"__Secure-sid (no Secure)"}},
		{"__Host- missing Path and has Domain", "https://e.test/", []string{"__Host-sid=1; Secure; Domain=e.test; Path=/app"}, model.StatusFail, model.SeverityError, []string{"__Host-sid (Path is not /, has Domain)"}},
		{"__Host- without Path", "https://e.test/", []string{"__Host-sid=1; Secure"}, model.StatusFail, model.SeverityError, []string{"Path is not /"}},
		{"__Host- correct", "https://e.test/", []string{"__Host-sid=1; Secure; Path=/; HttpOnly; SameSite=Strict"}, model.StatusPass, "", nil},
		{"prefix is case-insensitive", "https://e.test/", []string{"__secure-sid=1; HttpOnly; SameSite=Lax"}, model.StatusFail, model.SeverityError, []string{"__secure-sid (no Secure)"}},
		{"prefix error outranks missing Secure", "https://e.test/", []string{"__Secure-a=1", "b=1"}, model.StatusFail, model.SeverityError, []string{"__Secure-a (no Secure)", "no Secure on HTTPS page: __Secure-a, b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var hdr []string
			for _, c := range tc.cookies {
				hdr = append(hdr, "Set-Cookie", c)
			}
			f := runOne(t, Cookies(), htmlPage(t, tc.url, "<p>x</p>", hdr...))
			want(t, f, tc.status, tc.sev)
			contains(t, f.Observed, tc.obs...)
			if strings.Contains(f.Observed, "SECRETVALUE") {
				t.Errorf("cookie value leaked into Observed: %q", f.Observed)
			}
		})
	}
}

func TestCookies_NeverPrintsValuesAndTruncates(t *testing.T) {
	var hdr []string
	for i := 0; i < 40; i++ {
		hdr = append(hdr, "Set-Cookie", "cookie_with_a_long_name_"+strings.Repeat("x", 10)+string(rune('a'+i%26))+string(rune('a'+i/26))+"=VALUE"+strings.Repeat("v", 50))
	}
	f := runOne(t, Cookies(), htmlPage(t, "https://e.test/", "<p>x</p>", hdr...))
	want(t, f, model.StatusFail, model.SeverityWarn)
	contains(t, f.Observed, "+")
	if strings.Contains(f.Observed, "VALUE") {
		t.Errorf("value leaked: %q", f.Observed)
	}
}

func TestMixedContent(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		html   string
		status model.Status
		sev    model.Severity
		obs    []string
	}{
		{"clean", "https://e.test/", `<script src="/a.js"></script><img src="https://cdn.test/a.png"><img src="//cdn.test/b.png"><a href="http://x.test/">link</a>`, model.StatusPass, "", nil},
		{"http page skipped", "http://e.test/", `<script src="http://x.test/a.js"></script>`, model.StatusSkipped, "", nil},
		{"script blocks", "https://e.test/", `<script src="http://evil.test/a.js"></script>`, model.StatusFail, model.SeverityError, []string{"blockable 1 (script 1)", "evil.test"}},
		{"stylesheet blocks", "https://e.test/", `<link rel="stylesheet" href="http://c.test/s.css">`, model.StatusFail, model.SeverityError, []string{"stylesheet 1"}},
		{"preload link is not a stylesheet", "https://e.test/", `<link rel="icon" href="http://c.test/f.ico">`, model.StatusPass, "", nil},
		{"iframe object embed block", "https://e.test/", `<iframe src="http://a.test/"></iframe><object data="http://b.test/x"></object><embed src="http://c.test/y">`, model.StatusFail, model.SeverityError, []string{"blockable 3", "iframe 1", "object 1", "embed 1"}},
		{"image only is warn", "https://e.test/", `<img src="http://i.test/a.png"><video src="http://v.test/a.mp4"><source src="http://v.test/b.mp4"></video><audio src="http://s.test/a.mp3"></audio>`, model.StatusFail, model.SeverityWarn, []string{"upgradable 4", "img 1", "audio 1", "video 1", "source 1"}},
		{"form action is warn", "https://e.test/", `<form action="http://f.test/submit"></form>`, model.StatusFail, model.SeverityWarn, []string{"insecure form action 1", "f.test"}},
		{"worst wins, uppercase scheme", "https://e.test/", `<img src="http://i.test/a.png"><script src="HTTP://s.test/a.js"></script><form action="http://f.test/"></form>`, model.StatusFail, model.SeverityError, []string{"blockable 1", "upgradable 1", "insecure form action 1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := runOne(t, MixedContent(), htmlPage(t, tc.url, "<html><body>"+tc.html+"</body></html>"))
			want(t, f, tc.status, tc.sev)
			contains(t, f.Observed, tc.obs...)
			if tc.status == model.StatusSkipped {
				contains(t, f.Reason, "not served over HTTPS")
			}
		})
	}
}

func TestMixedContent_FirstThreeHostsOnly(t *testing.T) {
	html := `<script src="http://h1.test/a"></script><script src="http://h2.test/a"></script><script src="http://h3.test/a"></script><script src="http://h4.test/a"></script>`
	f := runOne(t, MixedContent(), htmlPage(t, "https://e.test/", html))
	contains(t, f.Observed, "blockable 4", "h1.test", "h2.test", "h3.test")
	if strings.Contains(f.Observed, "h4.test") {
		t.Errorf("listed more than 3 hosts: %q", f.Observed)
	}
}

func TestMixedContent_NoDocEmitsNothing(t *testing.T) {
	fs, err := MixedContent().Run(stubCtx{model.PageData{FinalURL: "https://e.test/"}})
	if err != nil || len(fs) != 0 {
		t.Errorf("got %v, %v; want no findings", fs, err)
	}
}

func TestVersionDisclosure(t *testing.T) {
	tests := []struct {
		name   string
		hdr    []string
		status model.Status
		obs    []string
	}{
		{"no headers", nil, model.StatusPass, nil},
		{"server without version", []string{"Server", "cloudflare"}, model.StatusPass, nil},
		{"server vercel", []string{"Server", "Vercel"}, model.StatusPass, nil},
		{"server with major only", []string{"Server", "nginx/1"}, model.StatusPass, nil},
		{"server with version", []string{"Server", "Apache/2.4.41 (Ubuntu)"}, model.StatusFail, []string{"Server: Apache/2.4.41 (Ubuntu)"}},
		{"x-powered-by", []string{"X-Powered-By", "Express"}, model.StatusFail, []string{"X-Powered-By: Express"}},
		{"aspnet", []string{"X-AspNet-Version", "4.0.30319", "X-AspNetMvc-Version", "5.2"}, model.StatusFail, []string{"X-AspNet-Version: 4.0.30319", "X-AspNetMvc-Version: 5.2"}},
		{"all together", []string{"Server", "nginx/1.18.0", "X-Powered-By", "PHP/8.2.1"}, model.StatusFail, []string{"X-Powered-By: PHP/8.2.1", "Server: nginx/1.18.0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := runOne(t, VersionDisclosure(), htmlPage(t, "https://e.test/", "<p>x</p>", tc.hdr...))
			if tc.status == model.StatusFail {
				want(t, f, model.StatusFail, model.SeverityWarn)
			} else {
				want(t, f, model.StatusPass, "")
			}
			contains(t, f.Observed, tc.obs...)
		})
	}
}

func TestSRI(t *testing.T) {
	tests := []struct {
		name   string
		html   string
		status model.Status
		obs    []string
	}{
		{"no scripts", `<p>x</p>`, model.StatusPass, nil},
		{"same-origin only", `<script src="/a.js"></script><script src="https://e.test/b.js"></script><script src="c.js"></script>`, model.StatusPass, nil},
		{"inline script ignored", `<script>var a=1</script>`, model.StatusPass, nil},
		{"third party with integrity", `<script src="https://cdn.test/a.js" integrity="sha384-abc" crossorigin="anonymous"></script>`, model.StatusPass, nil},
		{"third party without", `<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>`, model.StatusInfo, []string{"1 third-party script(s)", "www.googletagmanager.com", "gtag.js", "Turnstile"}},
		{"scheme-relative", `<script src="//challenges.cloudflare.com/turnstile/v0/api.js"></script>`, model.StatusInfo, []string{"challenges.cloudflare.com"}},
		{"empty integrity counts as missing", `<script src="https://cdn.test/a.js" integrity=" "></script>`, model.StatusInfo, []string{"cdn.test"}},
		{"hosts deduped", `<script src="https://a.test/1.js"></script><script src="https://a.test/2.js"></script>`, model.StatusInfo, []string{"2 third-party script(s)", "from a.test."}},
		{"host case-insensitive", `<script src="https://E.TEST/a.js"></script>`, model.StatusPass, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := runOne(t, SRI(), htmlPage(t, "https://e.test/", "<html><body>"+tc.html+"</body></html>"))
			want(t, f, tc.status, "")
			contains(t, f.Observed, tc.obs...)
		})
	}
}

func TestSRI_CapsHostList(t *testing.T) {
	var b strings.Builder
	for _, h := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		b.WriteString(`<script src="https://` + h + `.test/x.js"></script>`)
	}
	f := runOne(t, SRI(), htmlPage(t, "https://page.test/", b.String()))
	contains(t, f.Observed, "7 third-party", "a.test", "e.test", "+2 more")
	if strings.Contains(f.Observed, "f.test") {
		t.Errorf("host list not capped: %q", f.Observed)
	}
}

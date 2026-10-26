package demo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Regression: RemoteAddr's ephemeral port must be stripped, or the rate
// limiter keys on a value that's different on every single connection from
// the same client — silently disabling rate limiting entirely. Caught live:
// six curl requests in a row from one machine all sailed through as "200 OK"
// because each one carried a different source port.
func TestClientIP_StripsPortFromRemoteAddr(t *testing.T) {
	r1 := &http.Request{RemoteAddr: "203.0.113.5:51234", Header: http.Header{}}
	r2 := &http.Request{RemoteAddr: "203.0.113.5:60000", Header: http.Header{}}
	ip1, ip2 := clientIP(r1, ""), clientIP(r2, "")
	if ip1 != ip2 {
		t.Fatalf("clientIP should ignore ephemeral port so repeat requests share a key: got %q and %q", ip1, ip2)
	}
	if ip1 != "203.0.113.5" {
		t.Errorf("clientIP = %q, want the bare IP 203.0.113.5", ip1)
	}
}

func TestClientIP_UsesConfiguredHeader(t *testing.T) {
	cases := []struct {
		name   string
		header string
		set    http.Header
		remote string
		want   string
	}{
		{"fly header", "Fly-Client-IP", http.Header{"Fly-Client-Ip": {"198.51.100.7"}}, "10.0.0.1:1234", "198.51.100.7"},
		{"first of comma list, trimmed", "X-Real-IP", http.Header{"X-Real-Ip": {" 198.51.100.7 , 10.0.0.2"}}, "10.0.0.1:1234", "198.51.100.7"},
		{"configured header absent falls back to RemoteAddr", "X-Real-IP", http.Header{}, "203.0.113.5:4000", "203.0.113.5"},
		{"configured header blank falls back to RemoteAddr", "X-Real-IP", http.Header{"X-Real-Ip": {"  "}}, "203.0.113.5:4000", "203.0.113.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tc.remote, Header: tc.set}
			if got := clientIP(r, tc.header); got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// Regression: on a platform that doesn't overwrite Fly-Client-IP (Vercel), a
// visitor could send their own and get a fresh rate-limit key per request.
// A client-supplied header must be ignored unless it is THE configured one.
func TestClientIP_IgnoresSpoofedHeaders(t *testing.T) {
	spoofed := http.Header{
		"Fly-Client-Ip":   {"192.0.2.99"},
		"X-Forwarded-For": {"192.0.2.98"},
		"X-Real-Ip":       {"192.0.2.97"},
	}
	for _, header := range []string{"", "Some-Other-Header"} {
		r := &http.Request{RemoteAddr: "203.0.113.5:4000", Header: spoofed}
		if got := clientIP(r, header); got != "203.0.113.5" {
			t.Errorf("header option %q: clientIP = %q, want RemoteAddr 203.0.113.5 (spoofed headers must be ignored)", header, got)
		}
	}
}

func TestNormalizeSubmittedURL(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"example.com", "https://example.com", true},
		{"https://example.com/page", "https://example.com/page", true},
		{"  example.com  ", "https://example.com", true},
		{"", "", false},
		{"ftp://example.com", "", false},
		{"not a url at all !!", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeSubmittedURL(tc.in)
		if ok != tc.wantOK {
			t.Errorf("normalizeSubmittedURL(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("normalizeSubmittedURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// End to end through the handler: once an IP has used its budget, the next
// POST is a 429 — before any Turnstile or network work happens (the target
// below would be rejected as private if the fetch were reached).
func TestHandleScan_RateLimited(t *testing.T) {
	store := testStore(t)
	srv, err := NewServer(Options{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < scansPerHour; i++ {
		if _, ok, err := store.Reserve(context.Background(), "203.0.113.77", "example.com", time.Hour, scansPerHour); err != nil || !ok {
			t.Fatalf("setup Reserve #%d = (%v, %v)", i+1, ok, err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(`{"url":"http://127.0.0.1/"}`))
	req.RemoteAddr = "203.0.113.77:5555"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", rec.Code)
	}
}

// A fetch that fails (here: a private target) must still finish the reserved
// row with the failure reason instead of leaving it "pending".
func TestHandleScan_FailedFetchFinishesRow(t *testing.T) {
	store := testStore(t)
	srv, err := NewServer(Options{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(`{"url":"http://127.0.0.1:1/"}`))
	req.RemoteAddr = "203.0.113.78:5555"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var errText string
	if err := store.db.QueryRow("SELECT error FROM scan_log WHERE remote_ip_hash = $1", store.hashIP("203.0.113.78")).Scan(&errText); err != nil {
		t.Fatal(err)
	}
	if errText == "" || errText == pendingMarker {
		t.Errorf("row error = %q, want the fetch failure reason", errText)
	}
}

// The security headers go on every response, including the API and error
// paths, not just the static page.
func TestServeHTTP_SecurityHeaders(t *testing.T) {
	srv, err := NewServer(Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"X-Robots-Tag":              "noindex",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"X-Frame-Options":           "DENY",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
		"Content-Security-Policy": "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; " +
			"frame-src https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
			"font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; " +
			"frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/"},
		{http.MethodGet, "/api/turnstile-sitekey"},
		{http.MethodGet, "/api/scan"},     // 405
		{http.MethodGet, "/no-such-file"}, // 404
	} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		for k, v := range want {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s %s (status %d): %s = %q, want %q", tc.method, tc.path, rec.Code, k, got, v)
			}
		}
	}
}

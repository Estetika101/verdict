package demo

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Estetika101/verdict/internal/checks/geo"
	"github.com/Estetika101/verdict/internal/checks/security"
	"github.com/Estetika101/verdict/internal/checks/seo"
	"github.com/Estetika101/verdict/internal/engine"
	"github.com/Estetika101/verdict/internal/model"
)

//go:embed assets/*
var assetsFS embed.FS

const (
	scansPerHour    = 5
	rateLimitWindow = time.Hour
	scanTimeout     = 25 * time.Second // page (≤10s) + up to three sidecars (≤5s each)
)

// Options configures a Server. Store, TurnstileSiteKey, and
// TurnstileSecretKey are all optional together: leave them zero to run
// without logging/rate-limiting and without human verification (e.g. local
// dev). Turnstile is on only when BOTH the site key (public, sent to the
// browser) and the secret key (private, used server-side) are set — a site
// key alone would render a widget nothing actually checks. With both set,
// TurnstileHostnames is required too: the allowlist of hostnames a token may
// have been solved on (this demo's own domain), so a token minted on another
// site using the same key isn't honoured here.
//
// ClientIPHeader names the ONE request header to trust for the visitor's IP.
// Empty (the default) means trust nothing but the connection's RemoteAddr,
// which is correct when the server is exposed directly. Set it only to a
// header your edge proxy overwrites on every request — "Fly-Client-IP" on
// Fly, "X-Real-IP" on Vercel. Trusting a header the platform does NOT
// overwrite lets any visitor mint a fresh rate-limit key per request by
// sending their own value, which silently turns rate limiting off.
//
// Rate limiting requires Store: it's implemented as a reservation against the
// same log table the scan is recorded in (see store.go's Reserve doc comment
// for why this replaced an in-memory version). Running the demo without a
// database means running it without rate limiting — acceptable for local
// development, not for a public deployment.
type Options struct {
	Store              *Store
	TurnstileSiteKey   string
	TurnstileSecretKey string
	TurnstileHostnames []string
	ClientIPHeader     string
	// GAMeasurementID turns on Google Analytics 4 page measurement ("G-…").
	// Empty means no gtag script is loaded and the CSP doesn't admit
	// Google's hosts at all — a self-hosted demo never phones home to
	// someone else's analytics property by default.
	GAMeasurementID string
}

// Server is the public demo endpoint: one visitor-submitted URL in, one
// hardened fetch, a fixed set of page-scoped checks, a logged result out.
type Server struct {
	store     *Store // nil disables both logging AND rate limiting
	checks    []model.Check
	mux       *http.ServeMux
	siteKey   string
	turnstile turnstileConfig // secret "" disables Turnstile verification entirely
	ipHeader  string          // "" means RemoteAddr only; see Options.ClientIPHeader
	gaID      string          // "" disables analytics; see Options.GAMeasurementID
	csp       string
}

// NewServer builds the demo server.
func NewServer(opts Options) (*Server, error) {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		return nil, fmt.Errorf("demo: %w", err)
	}

	// Every page-scoped check runs — they need nothing beyond the fetched
	// page, so that filter is by scope and stays correct as checks are added
	// upstream. Site-scoped checks run only when named in sidecarChecks:
	// whether one is safe here depends on which URLs its code fetches, which
	// its scope can't tell us (see sidecar.go).
	var pageChecks []model.Check
	for _, c := range allCandidateChecks() {
		if m := c.Meta(); m.Scope == model.ScopePage || sidecarChecks[m.ID] {
			pageChecks = append(pageChecks, c)
		}
	}

	s := &Server{
		store:    opts.Store,
		checks:   pageChecks,
		ipHeader: opts.ClientIPHeader,
	}
	// Both keys required, or neither counts — see the Options doc comment.
	if opts.TurnstileSiteKey != "" && opts.TurnstileSecretKey != "" {
		// Refuse to start rather than run a widget whose tokens could never
		// verify (or, worse, would verify from any site): a misconfigured
		// deploy should fail loudly at boot, not reject every visitor quietly.
		if len(opts.TurnstileHostnames) == 0 {
			return nil, errors.New("demo: Turnstile is configured but no hostnames are allowed — set TURNSTILE_HOSTNAMES / --turnstile-hostnames to this demo's domain")
		}
		s.siteKey = opts.TurnstileSiteKey
		s.turnstile = turnstileConfig{secret: opts.TurnstileSecretKey, hostnames: opts.TurnstileHostnames}
	}

	if opts.GAMeasurementID != "" {
		if !gaIDPattern.MatchString(opts.GAMeasurementID) {
			return nil, fmt.Errorf("demo: %q is not a GA4 measurement ID (expected G-XXXXXXXXXX)", opts.GAMeasurementID)
		}
		s.gaID = opts.GAMeasurementID
	}
	s.csp = buildCSP(s.gaID != "")

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/config", s.handleConfig)
	s.mux = mux

	return s, nil
}

// handleConfig hands the frontend its PUBLIC runtime config — never a
// secret — so optional third-party scripts load only when configured:
//   - sitekey: the Turnstile site key, or "" when Turnstile is off; the
//     frontend then skips the widget entirely, matching handleScan's own
//     skip-when-unset behaviour. The action comes from here too, so the
//     widget and verifyTurnstile can't drift apart on its name.
//   - gaMeasurementId: the GA4 ID, or "" for no analytics script at all.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]string{
		"sitekey":         s.siteKey,
		"action":          turnstileAction,
		"gaMeasurementId": s.gaID,
	})
}

var gaIDPattern = regexp.MustCompile(`^G-[A-Z0-9]{4,20}$`)

func allCandidateChecks() []model.Check {
	all := security.All()
	all = append(all, seo.All()...)
	all = append(all, geo.All()...)
	return all
}

// buildCSP returns the demo page's whole policy. Scripts load only from this origin
// (the frontend serves /app.js rather than inlining) plus Cloudflare's
// Turnstile; styles allow inline for the page's own <style> and Google Fonts'
// stylesheet, with the font files from gstatic. connect-src 'self' is enough
// because the page only calls its own /api endpoints. frame-ancestors, base-uri
// and form-action close the clickjacking, <base>-injection and form-hijack
// routes that default-src doesn't cover.
//
// With analytics on, Google's GA4 hosts are added exactly where Google's CSP
// guidance puts them (gtag.js from googletagmanager; beacons as image and
// fetch requests to google-analytics / analytics.google.com) — and nowhere
// when it's off.
func buildCSP(analytics bool) string {
	script, img, connect := "", "", ""
	if analytics {
		script = " https://*.googletagmanager.com"
		img = " https://*.google-analytics.com https://*.googletagmanager.com"
		connect = " https://*.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com"
	}
	return "default-src 'self'; " +
		"script-src 'self' https://challenges.cloudflare.com" + script + "; " +
		"frame-src https://challenges.cloudflare.com; " +
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
		"font-src https://fonts.gstatic.com; " +
		"img-src 'self' data:" + img + "; " +
		"connect-src 'self'" + connect + "; " +
		"frame-ancestors 'none'; " +
		"base-uri 'none'; " +
		"form-action 'self'"
}

// ServeHTTP sets the security headers on EVERY response — pages, API replies,
// errors, 404s — by setting them before dispatch rather than per handler, so a
// new route can't forget them. HSTS is meaningful only over HTTPS and browsers
// ignore it on plain HTTP, so it is safe to send unconditionally.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Robots-Tag", "noindex") // the scan tool itself isn't a page worth indexing
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Content-Security-Policy", s.csp)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	started := time.Now()
	ip := clientIP(r, s.ipHeader)
	ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
	defer cancel()

	var body struct {
		URL            string `json:"url"`
		TurnstileToken string `json:"turnstileToken"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	target, ok := normalizeSubmittedURL(body.URL)
	if !ok {
		http.Error(w, "please provide a valid http(s) URL to scan", http.StatusBadRequest)
		return
	}

	// Rate limiting is a reservation, taken BEFORE the slow work, not a count
	// taken before and a log written after (see Store.Reserve for the race
	// that replaced). It runs after the body is parsed so malformed requests
	// don't burn a slot, and before Turnstile and the fetch so a visitor over
	// the limit costs us one small query and nothing else. A rejected-for-
	// rate-limit attempt is deliberately NOT logged: it adds no new
	// information (the rows that triggered the rejection are already in the
	// table) and logging every throttled hit would itself be a cheap way to
	// make this endpoint do more work under abuse, not less.
	var scanID int64
	if s.store != nil {
		id, allowed, err := s.store.Reserve(ctx, ip, hostnameOf(target), rateLimitWindow, scansPerHour)
		switch {
		case err != nil:
			// Fail open: a database hiccup shouldn't take the demo down. With
			// no reserved row there is nothing to Finish (scanID stays 0).
			log.Printf("demo: rate limit reservation failed, allowing request: %v", err)
		case !allowed:
			http.Error(w, fmt.Sprintf("rate limit exceeded — max %d scans/hour, try again later", scansPerHour), http.StatusTooManyRequests)
			return
		default:
			scanID = id
		}
	}

	// Turnstile verification only runs when a secret key is configured
	// (see Options' doc comment) — local/dev runs without one work exactly
	// as before. A verification failure is reported to the visitor as
	// exactly that, not folded into the generic scan-failure path. It still
	// finishes the reserved row, so the log shows why it never scanned.
	if s.turnstile.secret != "" {
		human, verr := verifyTurnstile(ctx, s.turnstile, body.TurnstileToken, ip)
		if verr != nil {
			s.finishScan(ctx, scanID, ScanLogEntry{Err: "turnstile verification unavailable: " + verr.Error()})
			http.Error(w, "verification check failed — please try again", http.StatusBadGateway)
			return
		}
		if !human {
			s.finishScan(ctx, scanID, ScanLogEntry{Err: "turnstile verification failed"})
			http.Error(w, "please complete the human verification and try again", http.StatusForbidden)
			return
		}
	}

	pd, err := safeFetch(ctx, target)
	if err != nil {
		s.finishScan(ctx, scanID, ScanLogEntry{Err: err.Error()})
		http.Error(w, "could not scan that URL: "+userFacingError(err), http.StatusBadRequest)
		return
	}

	cc := newDemoCheckContext(ctx, pd)
	var findings []model.Finding
	for _, c := range s.checks {
		fs, cerr := c.Run(cc)
		if cerr != nil {
			continue
		}
		findings = append(findings, fs...)
	}
	engine.AssignIDs(findings)
	engine.SortFindings(findings)
	summary := model.Summarize(findings)

	s.finishScan(ctx, scanID, ScanLogEntry{
		ErrorCount: countBySeverity(findings, model.SeverityError),
		WarnCount:  countBySeverity(findings, model.SeverityWarn),
		PassCount:  summary.Pass, SkipCount: summary.Skipped, InfoCount: summary.Info,
	})

	// The trace is the scan log the page replays: every request actually
	// made, and every check actually run, in order. Nothing in it is
	// decorative — the frontend paces it out, but doesn't add to it.
	checks := make([]map[string]string, 0, len(s.checks))
	for _, c := range s.checks {
		m := c.Meta()
		checks = append(checks, map[string]string{"id": m.ID, "module": m.Module, "title": m.Title})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]any{
		"url":      pd.FinalURL,
		"summary":  summary,
		"findings": findings,
		"trace": map[string]any{
			"page":      FetchEvent{What: "page", URL: pd.FinalURL, Status: pd.Status, Bytes: len(pd.Body), Ms: pd.TimingMs},
			"fetches":   cc.trace,
			"checks":    checks,
			"elapsedMs": time.Since(started).Milliseconds(),
		},
	})
}

// finishScan is synchronous, deliberately not a fire-and-forget goroutine: on
// any host that can freeze or tear down a process/instance immediately after
// a response is sent (which includes serverless platforms, but is not
// guaranteed to exclude a persistent host either during a deploy or restart),
// a detached goroutine racing that teardown can simply never complete,
// silently leaving the row on "pending". A synchronous call with a bounded
// timeout costs a little latency but guarantees the write is at least
// attempted before the handler returns. A logging failure still never fails
// the visitor's actual request — it's just written to stderr instead of the
// log table.
//
// The write runs on a context detached from ctx's cancellation: the scan
// context carries the scan deadline, and a scan that timed out is exactly
// the outcome most worth recording — deriving from the expired ctx would fail
// the write instead. id 0 means no row was reserved (no store, or the
// reservation failed open), so there is nothing to finish.
func (s *Server) finishScan(ctx context.Context, id int64, e ScanLogEntry) {
	if s.store == nil || id == 0 {
		return
	}
	logCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if err := s.store.Finish(logCtx, id, e); err != nil {
		log.Printf("demo: finish scan failed: %v", err)
	}
}

// clientIP returns the visitor's address for rate limiting and Turnstile.
//
// With header empty it uses RemoteAddr alone. With header set it reads that
// one header (first comma-separated field, trimmed) and falls back to
// RemoteAddr when the header is absent or blank. Only the single configured
// header is ever consulted: honouring a fixed list (Fly-Client-IP, then
// X-Forwarded-For) means a visitor on a platform that sets a different header
// can send their own value for the other and pick their own rate-limit key.
//
// RemoteAddr is host:port — the port is a fresh ephemeral value on every
// connection, so it MUST be stripped or the rate limiter silently never sees
// a repeat key (caught live: curling the same "attacker" six times in a row
// from one machine all landed as distinct keys and every request sailed
// through).
func clientIP(r *http.Request, header string) string {
	if header != "" {
		if v := r.Header.Get(header); v != "" {
			if first := strings.TrimSpace(strings.Split(v, ",")[0]); first != "" {
				return first
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// normalizeSubmittedURL applies the one UX nicety a "paste a URL" box needs:
// default to https:// when the visitor typed a bare domain.
func normalizeSubmittedURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	return u.String(), true
}

func countBySeverity(findings []model.Finding, sev model.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Status == model.StatusFail && f.Severity == sev {
			n++
		}
	}
	return n
}

func hostnameOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

// userFacingError avoids leaking raw internal error text (which can include
// resolved IPs, internal timeouts, etc.) to an anonymous caller — map the
// known safety-guard errors to a clear message, generic-ify the rest.
func userFacingError(err error) string {
	switch {
	case errors.Is(err, ErrPrivateIP):
		return "that address isn't a public site Verdict can reach"
	case errors.Is(err, ErrBadScheme):
		return "only http and https URLs are supported"
	case errors.Is(err, ErrTooManyRedirects):
		return "too many redirects"
	default:
		return "the request timed out or the site couldn't be reached"
	}
}

// Package demo implements the public, unauthenticated "try it live" scan
// endpoint for the marketing site — a single visitor-submitted URL, fetched
// once, checked, logged, shown. It is deliberately NOT built on
// internal/engine's multi-fetch Fetcher: that's tuned for a trusted local
// crawl (politeness, budget, cache across many fetches), and reusing it here
// would multiply the SSRF surface across every URL a site-scoped check might
// fetch (sitemap.xml, robots.txt, hreflang alternates...). The demo runs
// exactly one fetch, through one hardened path, and only page-scoped checks
// that need nothing beyond that one response.
package demo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Estetika101/verdict/internal/model"
	"github.com/PuerkitoBio/goquery"
)

const (
	maxBodyBytes  = 5 << 20 // 5 MiB cap so a huge/malicious response can't exhaust memory
	fetchTimeout  = 10 * time.Second
	maxRedirects  = 5
	demoUserAgent = "verdict-demo/0.1 (+https://verdict.estetika.org)"
)

var (
	ErrBadScheme        = errors.New("only http and https URLs are allowed")
	ErrPrivateIP        = errors.New("that address resolves to a private, loopback, or otherwise non-public IP and can't be scanned")
	ErrTooManyRedirects = errors.New("too many redirects")
)

// safeFetch fetches rawURL exactly once, validating at TWO points, not one:
//   - before dialing, so an obviously-private URL is rejected fast with a clear
//     error instead of an opaque connection failure;
//   - AT DIAL TIME, via the transport's DialContext, which validates the actual
//     IP the OS is about to connect to. This is what closes the real gap: a
//     hostname can resolve to a public IP when checked and a private one moments
//     later (DNS rebinding, or just a very short TTL) — checking once up front
//     and trusting it is a well-known SSRF bypass in exactly this kind of
//     "fetch a URL for the user" service. Redirects are validated the same way,
//     per hop, for the same reason: a 302 is just another fetch.
func safeFetch(ctx context.Context, rawURL string) (model.PageData, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return model.PageData{}, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return model.PageData{}, ErrBadScheme
	}
	if err := preflightCheck(ctx, u.Hostname()); err != nil {
		return model.PageData{}, err
	}

	client := &http.Client{
		Timeout: fetchTimeout,
		// A fresh Transport is built per scan, so connection reuse buys
		// nothing and an idle pool is pure leak: with keep-alives on and no
		// IdleConnTimeout, every scan would leave a connection (and its
		// goroutines) parked until the remote end closed it — forever, on
		// a long-lived process. DisableKeepAlives closes the connection when
		// the response body is closed.
		//
		// The remaining fields bound the phases the overall Client.Timeout
		// would otherwise be the only guard for, and shut off ambient
		// config: Proxy is nil explicitly so HTTP(S)_PROXY in the
		// environment can never route a visitor-chosen fetch through a proxy
		// that sits outside guardedDialContext's view (the dial guard would
		// then be checking the proxy's IP, not the target's).
		Transport: &http.Transport{
			DialContext:            guardedDialContext,
			DisableKeepAlives:      true,
			Proxy:                  nil,
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  fetchTimeout,
			MaxResponseHeaderBytes: 64 << 10,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return ErrTooManyRedirects
			}
			// Each redirect target gets the same preflight check before the
			// client follows it — a malicious server could otherwise pass
			// the initial check, then 302 to an internal address.
			return preflightCheck(req.Context(), req.URL.Hostname())
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return model.PageData{}, err
	}
	req.Header.Set("User-Agent", demoUserAgent)

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return model.PageData{}, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return model.PageData{}, fmt.Errorf("reading response: %w", err)
	}

	pd := model.PageData{
		RequestedURL: rawURL,
		FinalURL:     resp.Request.URL.String(),
		Status:       resp.StatusCode,
		Headers:      resp.Header,
		Body:         body,
		TimingMs:     time.Since(start).Milliseconds(),
		FetchedAt:    time.Now(),
	}
	if strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		if doc, derr := goquery.NewDocumentFromReader(bytes.NewReader(body)); derr == nil {
			pd.Doc = doc
		}
	}
	return pd, nil
}

// preflightCheck resolves host and rejects it if ANY resolved address is
// private, loopback, link-local, unspecified, or multicast. Run both before
// the initial dial and again (via CheckRedirect) before following a redirect.
func preflightCheck(ctx context.Context, host string) error {
	if host == "" {
		return ErrBadScheme
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("could not resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no addresses found for %s", host)
	}
	for _, a := range addrs {
		if isDisallowedIP(a.IP) {
			return ErrPrivateIP
		}
	}
	return nil
}

// guardedDialContext is the transport-level backstop: it validates the
// specific IP the standard library is about to open a TCP connection to,
// which is the actual moment that matters for SSRF — not whatever an earlier
// DNS lookup happened to return.
func guardedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// The transport hands DialContext the HOSTNAME:port straight from
		// the URL — it does not pre-resolve — so this is the normal path,
		// not a fallback. We resolve here, check the result, and then dial
		// that exact IP (below), so the address that was validated is the
		// address connected to; a second lookup inside the dialer could
		// return something different (DNS rebinding). An IP-literal URL
		// skips the lookup and is validated as-is.
		addrs, rerr := net.DefaultResolver.LookupIPAddr(ctx, host)
		if rerr != nil || len(addrs) == 0 {
			return nil, fmt.Errorf("could not resolve %s at dial time", host)
		}
		ip = addrs[0].IP
	}
	if isDisallowedIP(ip) {
		return nil, ErrPrivateIP
	}
	d := net.Dialer{Timeout: fetchTimeout}
	return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

// isDisallowedIP rejects loopback, private (RFC1918/RFC4193), link-local,
// unspecified, and multicast ranges — the address classes that would let a
// public-internet request reach internal infrastructure (a cloud metadata
// endpoint, an internal service, the host running this code itself).
func isDisallowedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}

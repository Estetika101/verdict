package security

import (
	"fmt"
	"strings"

	"github.com/Estetika101/verdict/internal/model"
)

// cookie is the parsed shape of one Set-Cookie header. The value is never
// kept: nothing downstream may print it.
type cookie struct {
	name     string
	secure   bool
	httpOnly bool
	sameSite bool
	path     string
	hasPath  bool
	domain   bool
}

// parseSetCookie reads the name and attributes of a Set-Cookie value.
// Attribute names are case-insensitive. A value with no "name=value" pair is
// not a cookie browsers store, so ok is false.
func parseSetCookie(raw string) (c cookie, ok bool) {
	parts := strings.Split(raw, ";")
	name, _, found := strings.Cut(parts[0], "=")
	name = strings.TrimSpace(name)
	if !found || name == "" {
		return cookie{}, false
	}
	c.name = name
	for _, attr := range parts[1:] {
		k, v, _ := strings.Cut(attr, "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "secure":
			c.secure = true
		case "httponly":
			c.httpOnly = true
		case "samesite":
			c.sameSite = strings.TrimSpace(v) != ""
		case "path":
			c.path, c.hasPath = strings.TrimSpace(v), true
		case "domain":
			c.domain = strings.TrimSpace(v) != ""
		}
	}
	return c, true
}

// prefixProblem reports how a cookie breaks its name-prefix rules, "" if it
// doesn't. Prefix matching is case-insensitive in RFC 6265bis.
func prefixProblem(c cookie) string {
	lower := strings.ToLower(c.name)
	switch {
	case strings.HasPrefix(lower, "__host-"):
		var miss []string
		if !c.secure {
			miss = append(miss, "no Secure")
		}
		if !c.hasPath || c.path != "/" {
			miss = append(miss, "Path is not /")
		}
		if c.domain {
			miss = append(miss, "has Domain")
		}
		if len(miss) > 0 {
			return c.name + " (" + strings.Join(miss, ", ") + ")"
		}
	case strings.HasPrefix(lower, "__secure-"):
		if !c.secure {
			return c.name + " (no Secure)"
		}
	}
	return ""
}

// Cookies returns the security-cookies check.
//
// WHY: a cookie without Secure can be sent over plain HTTP and read in
// transit; a cookie whose __Secure-/__Host- name promises protections it
// doesn't have is silently rejected by the browser, so the feature it was
// meant to enable (usually a session) just doesn't work. Sources: MDN,
// "Set-Cookie"
// (https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
// and the cookie-prefix rules in RFC 6265bis
// (https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/).
//
// Severity: broken prefix rules are fail/error (the cookie is rejected);
// missing Secure on an HTTPS page is fail/warn. A missing HttpOnly or
// SameSite is reported as an info note only: HttpOnly is legitimately absent
// on cookies that client-side JavaScript must read, and browsers already
// default an absent SameSite to Lax.
//
// It reads only this one response's Set-Cookie headers, so cookies set by
// scripts, or by other pages, are out of view. It never reads or prints
// cookie values; names only. Secure on an HTTP page is not flagged: browsers
// refuse to store a Secure cookie there, and security-https reports the page.
func Cookies() model.Check {
	return pageCheck{
		id: "security-cookies", title: "Cookie security attributes", severity: model.SeverityError,
		run: func(p model.PageData, _ model.Location) model.Finding {
			var cookies []cookie
			for _, raw := range p.Headers.Values("Set-Cookie") {
				if c, ok := parseSetCookie(raw); ok {
					cookies = append(cookies, c)
				}
			}
			if len(cookies) == 0 {
				return model.Finding{Status: model.StatusPass, Observed: "no cookies set on this response"}
			}

			https := isHTTPS(p)
			var prefix, noSecure, noHTTPOnly, noSameSite []string
			for _, c := range cookies {
				if pp := prefixProblem(c); pp != "" {
					prefix = append(prefix, pp)
				}
				if https && !c.secure {
					noSecure = append(noSecure, c.name)
				}
				if !c.httpOnly {
					noHTTPOnly = append(noHTTPOnly, c.name)
				}
				if !c.sameSite {
					noSameSite = append(noSameSite, c.name)
				}
			}

			var parts []string
			add := func(label string, items []string) {
				if len(items) > 0 {
					parts = append(parts, fmt.Sprintf("%s: %s", label, listN(items, 4)))
				}
			}
			add("broken prefix rules (browser rejects)", prefix)
			add("no Secure on HTTPS page", noSecure)
			add("no HttpOnly", noHTTPOnly)
			add("no SameSite (browsers default to Lax)", noSameSite)

			if len(parts) == 0 {
				return model.Finding{Status: model.StatusPass, Observed: fmt.Sprintf("%d cookie(s) set, all with Secure, HttpOnly and SameSite", len(cookies))}
			}
			observed := clip(fmt.Sprintf("%d cookie(s) set. %s", len(cookies), strings.Join(parts, "; ")), maxObserved)

			switch {
			case len(prefix) > 0:
				return model.Finding{
					Status: model.StatusFail, Severity: model.SeverityError, Observed: observed,
					Required:     "__Secure- cookies set with Secure; __Host- cookies set with Secure, Path=/ and no Domain",
					SuggestedFix: "Add the missing attributes to the Set-Cookie header, or drop the __Secure-/__Host- prefix from the name.",
				}
			case len(noSecure) > 0:
				return model.Finding{
					Status: model.StatusFail, Severity: model.SeverityWarn, Observed: observed,
					Required:     "Secure attribute on every cookie set over HTTPS",
					SuggestedFix: "Add Secure to these cookies' Set-Cookie headers.",
				}
			default:
				return model.Finding{Status: model.StatusInfo, Observed: observed}
			}
		},
	}
}

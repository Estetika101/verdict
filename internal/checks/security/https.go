package security

import (
	"strings"

	"github.com/Estetika101/verdict/internal/model"
)

// HTTPS returns the security-https check.
//
// WHY: a page served over plain HTTP can be read and rewritten in transit by
// anyone on the path, and browsers mark it "Not secure". It is also the
// precondition for HSTS, Secure cookies and most modern web platform
// features. Sources: MDN, "Strict-Transport-Security" and web.dev, "Why HTTPS
// matters" (https://web.dev/articles/why-https-matters).
//
// It looks only at the scheme of the final URL, after redirects. It
// deliberately does NOT judge HSTS (the security-headers check owns that), the
// certificate, or the TLS version: none of those are visible on a fetched
// response.
func HTTPS() model.Check {
	return pageCheck{
		id: "security-https", title: "Served over HTTPS", severity: model.SeverityError,
		run: func(p model.PageData, _ model.Location) model.Finding {
			if isHTTPS(p) {
				return model.Finding{Status: model.StatusPass}
			}
			observed := "page served over plain HTTP"
			if strings.HasPrefix(strings.ToLower(p.RequestedURL), "https://") {
				observed = "redirected from HTTPS to HTTP"
			}
			return model.Finding{
				Status: model.StatusFail, Severity: model.SeverityError,
				Observed:     clip(observed+": "+pageURL(p), maxObserved),
				Required:     "page served over HTTPS",
				SuggestedFix: "Serve the site over HTTPS, redirect HTTP to HTTPS, and then add Strict-Transport-Security.",
			}
		},
	}
}

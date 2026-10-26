package security

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/Estetika101/verdict/internal/model"
)

var versionRe = regexp.MustCompile(`\d+(\.\d+)+`)

// disclosureHeaders are always reported when present: they exist only to name
// the framework or runtime behind the site.
var disclosureHeaders = []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}

// VersionDisclosure returns the security-version-disclosure check.
//
// WHY: X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version and a Server header
// carrying a version number tell an attacker which known vulnerabilities to
// try, and give the site's owner nothing back. Source: OWASP Secure Headers
// Project, "Headers to remove"
// (https://owasp.org/www-project-secure-headers/).
//
// The values it prints are product names and version numbers, not secrets, so
// they go into Observed verbatim (clipped). It deliberately does NOT judge a
// bare product name in Server ("cloudflare", "Vercel", "nginx"): that is
// not a version, and hiding it is security through obscurity. It also doesn't
// check whether the disclosed version is actually vulnerable.
func VersionDisclosure() model.Check {
	return pageCheck{
		id: "security-version-disclosure", title: "Server software disclosure", severity: model.SeverityWarn,
		run: func(p model.PageData, _ model.Location) model.Finding {
			var found []string
			for _, name := range disclosureHeaders {
				if v := headerValue(p.Headers, name); v != "" {
					found = append(found, name+": "+clip(v, 60))
				}
			}
			if v := headerValue(p.Headers, "Server"); v != "" && versionRe.MatchString(v) {
				found = append(found, "Server: "+clip(v, 60))
			}
			if len(found) == 0 {
				return model.Finding{Status: model.StatusPass}
			}
			return model.Finding{
				Status: model.StatusFail, Severity: model.SeverityWarn,
				Observed:     clip(strings.Join(found, "; "), maxObserved),
				Required:     "no X-Powered-By / X-AspNet-Version / X-AspNetMvc-Version header, and no version number in Server",
				SuggestedFix: "Remove these headers (or strip the version from Server) in the web server, framework or CDN config.",
			}
		},
	}
}

// headerValue returns all values of a header joined, trimmed; "" when absent.
func headerValue(h http.Header, name string) string {
	return strings.TrimSpace(strings.Join(h.Values(name), ", "))
}

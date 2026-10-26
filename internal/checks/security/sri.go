package security

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Estetika101/verdict/internal/model"
	"github.com/PuerkitoBio/goquery"
)

// SRI returns the security-sri check.
//
// WHY: Subresource Integrity lets the page pin a script to a hash, so a
// compromised CDN can't swap in different code. Source: MDN, "Subresource
// Integrity"
// (https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity).
//
// It lists third-party scripts (a host different from the page's) that carry
// no integrity attribute. The result is info, never a fail, because SRI only
// works for versioned, static files. Loaders such as gtag.js or Cloudflare
// Turnstile change per request, so a hash would break them the next time the
// vendor ships, and a "fix" would be to remove the integration. Whether a
// given script can carry a hash is the owner's call; this check only reports
// which ones don't.
//
// "Third-party" means a different hostname: www.example.com and example.com
// count as different. It does not look at scripts injected at runtime,
// stylesheets, or whether an integrity value matches the file.
func SRI() model.Check {
	return pageCheck{
		id: "security-sri", title: "Subresource Integrity on third-party scripts", severity: model.SeverityWarn,
		run: func(p model.PageData, _ model.Location) model.Finding {
			if p.Doc == nil {
				return model.Finding{}
			}
			base, err := url.Parse(pageURL(p))
			if err != nil {
				return model.Finding{}
			}
			pageHost := strings.ToLower(base.Hostname())

			var hosts []string
			seen := map[string]bool{}
			count := 0
			p.Doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
				src, _ := s.Attr("src")
				ref, err := url.Parse(strings.TrimSpace(src))
				if err != nil {
					return
				}
				host := strings.ToLower(base.ResolveReference(ref).Hostname())
				if host == "" || host == pageHost {
					return
				}
				if integ, _ := s.Attr("integrity"); strings.TrimSpace(integ) != "" {
					return
				}
				count++
				if !seen[host] {
					seen[host] = true
					hosts = append(hosts, host)
				}
			})
			if count == 0 {
				return model.Finding{Status: model.StatusPass}
			}
			return model.Finding{
				Status: model.StatusInfo,
				Observed: clip(fmt.Sprintf("%d third-party script(s) without integrity, from %s. SRI needs a fixed, versioned file; loaders like gtag.js or Turnstile change per request and can't carry a hash.",
					count, listN(hosts, 5)), maxObserved),
			}
		},
	}
}

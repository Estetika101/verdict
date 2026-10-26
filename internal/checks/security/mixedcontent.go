package security

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Estetika101/verdict/internal/model"
	"github.com/PuerkitoBio/goquery"
)

// mixedRule is one element/attribute pair that loads or submits to a URL.
type mixedRule struct {
	label    string // shown in Observed
	selector string
	attr     string
}

// Active content: browsers block it outright on an HTTPS page.
var blockableRules = []mixedRule{
	{"script", "script[src]", "src"},
	{"iframe", "iframe[src]", "src"},
	{"stylesheet", "link[rel~=stylesheet][href]", "href"},
	{"object", "object[data]", "data"},
	{"embed", "embed[src]", "src"},
}

// Passive content: modern browsers upgrade it to HTTPS, or block it.
var upgradableRules = []mixedRule{
	{"img", "img[src]", "src"},
	{"audio", "audio[src]", "src"},
	{"video", "video[src]", "src"},
	{"source", "source[src]", "src"},
}

var formRules = []mixedRule{{"form", "form[action]", "action"}}

// MixedContent returns the security-mixed-content check.
//
// WHY: an HTTPS page that pulls a script, frame or stylesheet over HTTP hands
// control of the page to anyone on the network path, so browsers block it and
// the feature silently breaks. Images and media are "upgradable": modern
// browsers rewrite them to HTTPS (or block them), so the damage is smaller,
// and a form that posts to an http:// URL sends what the visitor typed in the
// clear. Sources: MDN, "Mixed content"
// (https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content) and
// W3C, "Mixed Content Level 2" (https://www.w3.org/TR/mixed-content/).
//
// One finding per page: the worst class sets the severity (blockable =
// error; upgradable or form action = warn). Observed gives counts per class
// and the hosts of the first three offending URLs, worst class first.
//
// It reads attributes in the server HTML only. It deliberately does NOT see
// resources a script adds later, URLs inside CSS or srcset, or subresource
// requests made by JavaScript, and it skips pages that aren't HTTPS (there is
// nothing to mix with; security-https reports those).
func MixedContent() model.Check {
	return pageCheck{
		id: "security-mixed-content", title: "Mixed content", severity: model.SeverityError,
		run: func(p model.PageData, _ model.Location) model.Finding {
			if !isHTTPS(p) {
				return model.Finding{Status: model.StatusSkipped, Reason: "page is not served over HTTPS"}
			}
			if p.Doc == nil {
				return model.Finding{} // no parsed HTML; nothing to check
			}

			var hosts []string
			scan := func(rules []mixedRule) (total int, summary string) {
				var parts []string
				for _, r := range rules {
					n := 0
					p.Doc.Find(r.selector).Each(func(_ int, s *goquery.Selection) {
						v, _ := s.Attr(r.attr)
						if !isHTTPURL(v) {
							return
						}
						n++
						hosts = append(hosts, urlHost(v))
					})
					if n > 0 {
						parts = append(parts, fmt.Sprintf("%s %d", r.label, n))
						total += n
					}
				}
				return total, strings.Join(parts, ", ")
			}

			blockN, blockS := scan(blockableRules)
			upN, upS := scan(upgradableRules)
			formN, _ := scan(formRules)
			if blockN+upN+formN == 0 {
				return model.Finding{Status: model.StatusPass}
			}

			var parts []string
			if blockN > 0 {
				parts = append(parts, fmt.Sprintf("blockable %d (%s)", blockN, blockS))
			}
			if upN > 0 {
				parts = append(parts, fmt.Sprintf("upgradable %d (%s)", upN, upS))
			}
			if formN > 0 {
				parts = append(parts, fmt.Sprintf("insecure form action %d", formN))
			}
			first := hosts
			if len(first) > 3 {
				first = first[:3]
			}
			first = dedupe(first)
			observed := clip("http:// URLs on an HTTPS page: "+strings.Join(parts, "; ")+". First hosts: "+strings.Join(first, ", "), maxObserved)

			if blockN > 0 {
				return model.Finding{
					Status: model.StatusFail, Severity: model.SeverityError, Observed: observed,
					Required:     "no http:// scripts, frames, stylesheets, objects or embeds on an HTTPS page (browsers block them)",
					SuggestedFix: "Load these resources over https:// (or from the same origin). Then fix the images, media and form actions too.",
				}
			}
			return model.Finding{
				Status: model.StatusFail, Severity: model.SeverityWarn, Observed: observed,
				Required:     "no http:// images, media or form actions on an HTTPS page",
				SuggestedFix: "Use https:// URLs. Browsers upgrade or block http:// media, and a form posting to http:// sends its fields unencrypted.",
			}
		},
	}
}

func isHTTPURL(v string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "http://")
}

func urlHost(v string) string {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Host == "" {
		return "(unparseable)"
	}
	return u.Host
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

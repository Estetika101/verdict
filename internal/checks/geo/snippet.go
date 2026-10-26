package geo

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Estetika101/verdict/internal/model"
	"github.com/PuerkitoBio/goquery"
)

// SnippetControls returns the geo-snippet-controls check. It reports which
// snippet directives Google will see on the page and what they mean for AI
// features.
//
// WHY: Google's robots meta tag documentation says nosnippet "will also
// prevent the content from being used as a direct input for AI Overviews and
// AI Mode", and that max-snippet "will also limit how much of the content may
// be used" there. max-snippet:0 is equivalent to nosnippet. Names and values
// are case-insensitive, and when rules conflict the more restrictive one wins.
// data-nosnippet is valid only on span, div and section elements; elsewhere it
// is ignored. Sources: Google Search Central, "Robots meta tag, data-nosnippet,
// and X-Robots-Tag specifications"
// (https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag)
// and "AI features and your website"
// (https://developers.google.com/search/docs/appearance/ai-features).
//
// Inputs are <meta name="robots|googlebot"> and every X-Robots-Tag header
// value; only unscoped rules and "googlebot:" rules apply to Google. The most
// restrictive combination is what gets reported.
//
// Deliberately NOT judged: whether a nosnippet or max-snippet limit is the
// right call. That is the owner's business decision about AI use, so it is
// reported as info in plain words. The one fail is the one verifiable defect:
// data-nosnippet on an element where Google ignores it. noindex is only noted
// — indexability belongs to the SEO module. noai/noimageai are noted as
// non-standard; Google does not read them.
func SnippetControls() model.Check {
	return pageDataCheck{id: "geo-snippet-controls", title: "Snippet controls for AI answers", run: snippetControls}
}

// knownRobotsDirectives lets the X-Robots-Tag parser tell "googlebot: nosnippet"
// (user-agent prefix) from "max-snippet:50" (directive with a value).
var knownRobotsDirectives = map[string]bool{
	"all": true, "none": true, "noindex": true, "nofollow": true, "noarchive": true,
	"nosnippet": true, "max-snippet": true, "max-image-preview": true,
	"max-video-preview": true, "notranslate": true, "noimageindex": true,
	"unavailable_after": true, "indexifembedded": true, "noai": true, "noimageai": true,
}

type snippetState struct {
	noSnippet  bool
	nosnipVia  map[string]bool
	maxSnippet int // smallest positive max-snippet seen; 0 = none
	maxVia     map[string]bool
	noindex    bool
	noai       bool
}

func (s *snippetState) apply(directives, via string) {
	for _, d := range strings.Split(directives, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		key, val, _ := strings.Cut(d, ":")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "nosnippet":
			s.noSnippet = true
			s.nosnipVia[via] = true
		case "max-snippet":
			n, err := strconv.Atoi(val)
			switch {
			case err != nil || n < 0:
				// -1 (Google chooses the length) or unparseable: not a limit.
			case n == 0:
				s.noSnippet = true // max-snippet:0 is equivalent to nosnippet
				s.nosnipVia[via] = true
			case s.maxSnippet == 0 || n < s.maxSnippet:
				s.maxSnippet = n
				s.maxVia = map[string]bool{via: true}
			case n == s.maxSnippet:
				s.maxVia[via] = true
			}
		case "noindex", "none":
			s.noindex = true
		case "noai", "noimageai":
			s.noai = true
		}
	}
}

func snippetControls(page model.PageData) model.Finding {
	st := &snippetState{nosnipVia: map[string]bool{}, maxVia: map[string]bool{}}

	page.Doc.Find("meta[name]").Each(func(_ int, s *goquery.Selection) {
		name := strings.ToLower(strings.TrimSpace(s.AttrOr("name", "")))
		if name != "robots" && name != "googlebot" {
			return
		}
		st.apply(s.AttrOr("content", ""), "meta "+name)
	})
	for _, h := range page.Headers.Values("X-Robots-Tag") {
		value := strings.TrimSpace(h)
		if left, rest, ok := strings.Cut(value, ":"); ok && !knownRobotsDirectives[strings.ToLower(strings.TrimSpace(left))] {
			// "<user-agent>: rules" — only unscoped or googlebot rules reach Google.
			if strings.ToLower(strings.TrimSpace(left)) != "googlebot" {
				continue
			}
			value = rest
		}
		st.apply(value, "X-Robots-Tag")
	}

	validNoSnip := 0
	badTags := map[string]int{}
	badCount := 0
	page.Doc.Find("[data-nosnippet]").Each(func(_ int, s *goquery.Selection) {
		tag := strings.ToLower(goquery.NodeName(s))
		switch tag {
		case "span", "div", "section":
			validNoSnip++
		default:
			badTags[tag]++
			badCount++
		}
	})

	var notes []string
	if validNoSnip > 0 {
		notes = append(notes, fmt.Sprintf("%d valid data-nosnippet element(s)", validNoSnip))
	}
	if st.noindex {
		notes = append(notes, "page also noindex — excluded from Search entirely; see SEO")
	}
	if st.noai {
		notes = append(notes, "noai/noimageai present — not recognised by Google; honoured only by some platforms")
	}

	join := func(m map[string]bool) string {
		var v []string
		for k := range m {
			v = append(v, k)
		}
		sort.Strings(v)
		return strings.Join(v, ", ")
	}
	suffix := ""
	if len(notes) > 0 {
		suffix = "; " + strings.Join(notes, "; ")
	}

	switch {
	case badCount > 0:
		var tags []string
		for t := range badTags {
			tags = append(tags, "<"+t+">")
		}
		sort.Strings(tags)
		obs := fmt.Sprintf("data-nosnippet on %d element(s) outside span, div, section (%s) — Google ignores it there", badCount, capList(tags, 5))
		if st.noSnippet {
			obs += "; nosnippet in effect (" + join(st.nosnipVia) + ")"
		}
		return model.Finding{
			Status: model.StatusFail, Severity: model.SeverityWarn,
			Observed: obs + suffix,
			Required: "data-nosnippet only on span, div or section",
			SuggestedFix: "Wrap the content in a <span>, <div> or <section> and put data-nosnippet on the wrapper; " +
				"Google ignores the attribute on any other element.",
		}
	case st.noSnippet:
		return model.Finding{
			Status:   model.StatusInfo,
			Observed: "nosnippet in effect (" + join(st.nosnipVia) + ") — Google won't use this page's text as direct input for AI Overviews or AI Mode" + suffix,
		}
	case st.maxSnippet > 0:
		return model.Finding{
			Status: model.StatusInfo,
			Observed: fmt.Sprintf("max-snippet:%d in effect (%s) — Google may use at most %d characters of this page's text as direct input for AI Overviews and AI Mode%s",
				st.maxSnippet, join(st.maxVia), st.maxSnippet, suffix),
		}
	case st.noai:
		return model.Finding{Status: model.StatusInfo, Observed: "no nosnippet or max-snippet limit" + suffix}
	}
	obs := "no nosnippet or max-snippet limit — Google may use this page's text as direct input for AI Overviews and AI Mode"
	return model.Finding{Status: model.StatusPass, Observed: obs + suffix}
}

// capList joins up to n items, then "+N more".
func capList(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" +%d more", len(items)-n)
}

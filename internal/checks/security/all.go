package security

import (
	"strconv"
	"strings"

	"github.com/Estetika101/verdict/internal/model"
)

// All returns every security check: the original response-headers check
// first, then the page-level checks added after it, in report order.
func All() []model.Check {
	return []model.Check{
		New(),
		HTTPS(),
		Cookies(),
		MixedContent(),
		VersionDisclosure(),
		SRI(),
	}
}

// pageCheck is the common shape for the single-finding security checks: a
// function of the fetched page that returns one Finding. A zero-Status
// result means "nothing to report" (for example, no parsed HTML for a check
// that needs the DOM) and emits no finding.
//
// It duplicates the few lines of wiring the geo and seo packages each carry
// rather than importing across check packages; the logic that matters lives
// in the run functions.
type pageCheck struct {
	id       string
	title    string
	severity model.Severity // default severity for this check's fails
	run      func(p model.PageData, loc model.Location) model.Finding
}

func (c pageCheck) Meta() model.CheckMeta {
	return model.CheckMeta{
		ID: c.id, Module: "security", Tier: 1, Scope: model.ScopePage,
		Severity: c.severity, Title: c.title,
	}
}

func (c pageCheck) Run(cc model.CheckContext) ([]model.Finding, error) {
	page := cc.Page()
	loc := model.Location{URL: pageURL(page)}
	f := c.run(page, loc)
	if f.Status == "" {
		return nil, nil
	}
	f.Module, f.Scope, f.Criterion = "security", model.ScopePage, c.id
	f.Location = loc
	return []model.Finding{f}, nil
}

func isHTTPS(p model.PageData) bool {
	return strings.HasPrefix(strings.ToLower(pageURL(p)), "https://")
}

// maxObserved is the soft ceiling for Observed strings.
const maxObserved = 300

// clip shortens s to at most n bytes (on a rune boundary), marking the cut.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n - 3
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "..."
}

// listN joins up to max items and appends "+N more" for the rest.
func listN(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + " +" + strconv.Itoa(len(items)-max) + " more"
}

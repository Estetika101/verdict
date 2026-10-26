package geo

import (
	"github.com/Estetika101/verdict/internal/model"
	"github.com/PuerkitoBio/goquery"
)

// pageCheck is the common shape for the page-scoped GEO checks: pure
// functions of the page's parsed DOM, one Finding per page. Mirrors the seo
// package's identical helper — a small, deliberate duplication (a few lines
// of registration plumbing) rather than a cross-package import, consistent
// with how internal/checks/seo keeps its own local URL helpers instead of
// reaching into engine internals. Unlike robots.txt group-parsing (extracted
// into internal/robotstxt because it's real logic worth sharing), this is
// just wiring — nothing here could drift in a way that matters.
type pageCheck struct {
	id    string
	title string
	run   func(doc *goquery.Document, loc model.Location) model.Finding
}

func (c pageCheck) Meta() model.CheckMeta {
	return model.CheckMeta{
		ID: c.id, Module: "geo", Tier: 1, Scope: model.ScopePage,
		Severity: model.SeverityWarn, Title: c.title,
	}
}

func (c pageCheck) Run(cc model.CheckContext) ([]model.Finding, error) {
	page := cc.Page()
	loc := model.Location{URL: pageURL(page)}
	if page.Doc == nil {
		return nil, nil // no parsed HTML (non-HTML response); nothing to check
	}
	f := c.run(page.Doc, loc)
	if f.Status == "" {
		return nil, nil
	}
	f.Module, f.Scope, f.Criterion = "geo", model.ScopePage, c.id
	if f.Location.URL == "" {
		f.Location = loc
	}
	return []model.Finding{f}, nil
}

// pageDataCheck is the page-scoped shape for checks that need more than the
// parsed DOM — response headers in particular (X-Robots-Tag). Same contract as
// pageCheck: a pure function of cc.Page(), one Finding per page, never a Fetch.
type pageDataCheck struct {
	id    string
	title string
	run   func(page model.PageData) model.Finding
}

func (c pageDataCheck) Meta() model.CheckMeta {
	return model.CheckMeta{
		ID: c.id, Module: "geo", Tier: 1, Scope: model.ScopePage,
		Severity: model.SeverityWarn, Title: c.title,
	}
}

func (c pageDataCheck) Run(cc model.CheckContext) ([]model.Finding, error) {
	page := cc.Page()
	if page.Doc == nil {
		return nil, nil // no parsed HTML (non-HTML response); nothing to check
	}
	loc := model.Location{URL: pageURL(page)}
	f := c.run(page)
	if f.Status == "" {
		return nil, nil
	}
	f.Module, f.Scope, f.Criterion = "geo", model.ScopePage, c.id
	if f.Location.URL == "" {
		f.Location = loc
	}
	return []model.Finding{f}, nil
}

// All returns every GEO check.
func All() []model.Check {
	return []model.Check{
		BotPosture(),
		LLMsTxt(),
		Freshness(),
		SnippetControls(),
		StructuredData(),
		ServerRenderedText(),
		ContentSignals(),
	}
}

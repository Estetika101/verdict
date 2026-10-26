package geo

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Estetika101/verdict/internal/model"
	"github.com/PuerkitoBio/goquery"
)

// StructuredData returns the geo-structured-data check. It reports whether the
// page's JSON-LD blocks parse and which @type values they declare.
//
// WHY: Google recommends JSON-LD as its structured-data format and says markup
// must be valid to work (Google Search Central, "Introduction to structured
// data markup in Google Search",
// https://developers.google.com/search/docs/appearance/structured-data/intro-structured-data).
// Google's AI features page is equally clear that there is "no special
// schema.org structured data that you need to add" for them
// (https://developers.google.com/search/docs/appearance/ai-features) — so a
// page with no JSON-LD is info, not a defect. JSON-LD 1.1 (W3C,
// https://www.w3.org/TR/json-ld11/) puts the vocabulary mapping in @context; a
// top-level node without one is plain JSON to a consumer.
//
// Fails are the two verifiable ones: a block that is not valid JSON, and a
// top-level object with no @context. Deliberately NOT judged: per-type required
// or recommended properties, rich-result eligibility, or whether the chosen
// types suit the page — that is the future structured-data module's job.
func StructuredData() model.Check {
	return pageCheck{id: "geo-structured-data", title: "Structured data (JSON-LD)", run: func(doc *goquery.Document, _ model.Location) model.Finding {
		var blocks []string
		doc.Find("script[type]").Each(func(_ int, s *goquery.Selection) {
			t := strings.ToLower(s.AttrOr("type", ""))
			t, _, _ = strings.Cut(t, ";")
			if strings.TrimSpace(t) == "application/ld+json" {
				blocks = append(blocks, s.Text())
			}
		})
		if len(blocks) == 0 {
			return model.Finding{
				Status:   model.StatusInfo,
				Observed: "no JSON-LD — Google says no special schema is needed for its AI features; JSON-LD remains its recommended structured-data format",
			}
		}

		bad, noContext := 0, 0
		firstErr := ""
		types := map[string]bool{}
		for _, b := range blocks {
			var v any
			if err := json.Unmarshal([]byte(b), &v); err != nil {
				bad++
				if firstErr == "" {
					firstErr = err.Error()
				}
				continue
			}
			missing := false
			for _, root := range ldRoots(v) {
				if _, ok := root["@context"]; !ok {
					missing = true
				}
			}
			if missing {
				noContext++
			}
			collectTypes(v, types)
		}

		var typeList []string
		for t := range types {
			typeList = append(typeList, t)
		}
		sort.Strings(typeList)
		typesNote := "no @type found"
		if len(typeList) > 0 {
			typesNote = "types: " + capList(typeList, 8)
		}

		if bad > 0 || noContext > 0 {
			var parts []string
			var required []string
			if bad > 0 {
				parts = append(parts, fmt.Sprintf("%d of %d JSON-LD blocks don't parse — engines ignore invalid markup (first error: %s)",
					bad, len(blocks), truncate(firstErr, 80)))
				required = append(required, "valid JSON in every JSON-LD block")
			}
			if noContext > 0 {
				parts = append(parts, fmt.Sprintf("%d block(s) without @context — JSON-LD without @context isn't interpretable as schema.org", noContext))
				required = append(required, `"@context": "https://schema.org" on each top-level JSON-LD object`)
			}
			return model.Finding{
				Status: model.StatusFail, Severity: model.SeverityWarn,
				Observed: strings.Join(parts, "; ") + "; " + typesNote,
				Required: strings.Join(required, "; "),
				SuggestedFix: "Run the markup through a JSON validator and Google's Rich Results Test; make sure each top-level " +
					`object declares "@context": "https://schema.org".`,
			}
		}
		return model.Finding{
			Status:   model.StatusPass,
			Observed: fmt.Sprintf("%d JSON-LD block(s) parse; %s", len(blocks), typesNote),
		}
	}}
}

// ldRoots returns the top-level objects of a decoded JSON-LD value: the object
// itself, or each object in a top-level array. @graph members share their
// parent's @context, so they are not roots.
func ldRoots(v any) []map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return []map[string]any{t}
	case []any:
		var out []map[string]any
		for _, item := range t {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// collectTypes walks objects, arrays and @graph, adding every @type (a string
// or an array of strings) to the set.
func collectTypes(v any, out map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		switch ty := t["@type"].(type) {
		case string:
			out[ty] = true
		case []any:
			for _, x := range ty {
				if s, ok := x.(string); ok {
					out[s] = true
				}
			}
		}
		for k, child := range t {
			if k == "@type" || k == "@context" {
				continue
			}
			collectTypes(child, out)
		}
	case []any:
		for _, item := range t {
			collectTypes(item, out)
		}
	}
}

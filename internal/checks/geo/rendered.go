package geo

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/Estetika101/verdict/internal/model"
	"github.com/PuerkitoBio/goquery"
)

// minServerWords is the "near-empty" floor, not a content-quality bar.
const minServerWords = 50

// appShellSelectors are the mount points client-side frameworks leave behind
// when the server sends no content of its own.
var appShellSelectors = []string{"#root", "#app", "#__next", "#__nuxt", "#svelte", "[data-reactroot]"}

// ServerRenderedText returns the geo-server-rendered-text check. It counts the
// visible words in the HTML the server sends, before any JavaScript runs.
//
// WHY: Vercel and MERJ's analysis of AI-crawler traffic, "The rise of the AI
// crawler" (2024-12-17, https://vercel.com/blog/the-rise-of-the-ai-crawler),
// found that "none of the major AI crawlers currently render JavaScript"
// (OAI-SearchBot, ChatGPT-User, GPTBot, ClaudeBot, PerplexityBot, Bytespider,
// Meta-ExternalAgent, CCBot), while Gemini (Googlebot's infrastructure) and
// AppleBot do. Their recommendation is server rendering for critical content.
// A page whose text only exists after JavaScript runs is, to most AI crawlers,
// a page with no text.
//
// Counted: text in <body>, excluding script, style, noscript, template, svg
// and anything with the hidden attribute. A client-side app shell (#root, #app,
// #__next, #__nuxt, #svelte or [data-reactroot] with nothing inside) is noted
// when found.
//
// Deliberately NOT judged: how much content is enough. 50 words is a floor for
// "near-empty", not a content-quality bar — Verdict doesn't judge length, and a
// short page that is fully in the HTML passes.
func ServerRenderedText() model.Check {
	return pageCheck{id: "geo-server-rendered-text", title: "Text in the server-rendered HTML", run: func(doc *goquery.Document, _ model.Location) model.Finding {
		words := 0
		var sb strings.Builder
		visibleText(doc.Find("body").First(), &sb)
		for _, w := range strings.Fields(sb.String()) {
			if strings.ContainsFunc(w, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) {
				words++
			}
		}

		if words >= minServerWords {
			return model.Finding{Status: model.StatusPass, Observed: fmt.Sprintf("%d words in the server HTML", words)}
		}

		observed := fmt.Sprintf("%d words in the server HTML", words)
		if shell := emptyAppShell(doc); shell != "" {
			observed += fmt.Sprintf("; empty %s app shell", shell)
		}
		observed += " — AI crawlers that don't run JavaScript (GPTBot, ClaudeBot, PerplexityBot) see almost nothing"
		return model.Finding{
			Status: model.StatusFail, Severity: model.SeverityWarn,
			Observed: observed,
			Required: "page's main content present in the HTML the server sends",
			SuggestedFix: "Render the primary content on the server (SSR, SSG or ISR) so it is in the first HTML response; " +
				"client-side hydration can add to it, but shouldn't be the only source of the text.",
		}
	}}
}

// skippedTags never contribute visible text.
var skippedTags = map[string]bool{"script": true, "style": true, "noscript": true, "template": true, "svg": true}

// inlineTags don't break a word boundary; everything else does.
var inlineTags = map[string]bool{
	"a": true, "abbr": true, "b": true, "bdi": true, "bdo": true, "cite": true, "code": true,
	"data": true, "dfn": true, "em": true, "i": true, "kbd": true, "mark": true, "q": true,
	"s": true, "samp": true, "small": true, "span": true, "strong": true, "sub": true,
	"sup": true, "time": true, "u": true, "var": true,
}

func visibleText(sel *goquery.Selection, sb *strings.Builder) {
	sel.Contents().Each(func(_ int, c *goquery.Selection) {
		name := goquery.NodeName(c)
		if name == "#text" {
			sb.WriteString(c.Text())
			return
		}
		if skippedTags[name] || c.Is("[hidden]") || strings.HasPrefix(name, "#") {
			return
		}
		boundary := !inlineTags[name]
		if boundary {
			sb.WriteByte(' ')
		}
		visibleText(c, sb)
		if boundary {
			sb.WriteByte(' ')
		}
	})
}

// emptyAppShell returns the selector of the first app-shell mount point that
// has no element children and only whitespace text, or "".
func emptyAppShell(doc *goquery.Document) string {
	for _, sel := range appShellSelectors {
		found := ""
		doc.Find(sel).EachWithBreak(func(_ int, s *goquery.Selection) bool {
			if s.Children().Length() == 0 && strings.TrimSpace(s.Text()) == "" {
				found = sel
				return false
			}
			return true
		})
		if found != "" {
			return found
		}
	}
	return ""
}

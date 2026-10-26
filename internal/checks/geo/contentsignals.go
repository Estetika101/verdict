package geo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Estetika101/verdict/internal/model"
)

// signalNames is the set of signals in Cloudflare's Content Signals Policy,
// in the order they're reported.
var signalNames = []string{"search", "ai-input", "ai-train"}

// ContentSignals returns the geo-content-signals check. It reads the
// Content-Signal lines in robots.txt and reports, per User-agent group, which
// signals the site owner declared.
//
// WHY: Cloudflare's Content Signals Policy ("Giving users choice with
// Cloudflare's new Content Signals Policy", 2025-09-24,
// https://blog.cloudflare.com/content-signals-policy/) adds a Content-Signal
// robots.txt field of comma-separated name=yes|no pairs, e.g.
// `Content-Signal: search=yes, ai-train=no`. The signals are search (building a
// search index and providing search results), ai-input (inputting content into
// AI models) and ai-train (training or fine-tuning AI models). A signal that is
// omitted "neither grants nor restricts permission".
//
// Always info, except for one verifiable defect: a key that isn't one of the
// three signals, or a value that isn't yes/no, is malformed. Deliberately NOT
// judged: whether to allow search, AI input or training — that is the owner's
// call, and an absent declaration is not a defect. Keys and values are matched
// case-insensitively; the policy doesn't say they're case-sensitive, so a
// defect isn't claimed on case alone.
func ContentSignals() model.Check {
	return siteCheck{id: "geo-content-signals", title: "Content Signals (robots.txt)", run: func(cc model.CheckContext) []model.Finding {
		root := siteRoot(cc)
		if root == "" {
			return nil
		}
		loc := model.Location{URL: root + "/robots.txt"}

		pd, err := cc.Fetch(context.Background(), loc.URL)
		switch {
		case errors.Is(err, model.ErrBudgetExhausted):
			return []model.Finding{{Status: model.StatusSkipped, Reason: "fetch budget exhausted", Location: loc}}
		case errors.Is(err, model.ErrBlocked):
			return []model.Finding{{Status: model.StatusSkipped, Reason: "blocked", Location: loc}}
		case errors.Is(err, model.ErrRobotsDisallowed):
			return []model.Finding{{Status: model.StatusSkipped, Reason: "disallowed by robots.txt", Location: loc}}
		}
		const none = "no Content-Signal declared — neither grants nor restricts AI use (Cloudflare Content Signals Policy)"
		if err != nil || pd.Status >= 400 {
			return []model.Finding{{Status: model.StatusInfo, Location: loc, Observed: none}}
		}

		groups, bad := parseContentSignals(pd.Body)
		if len(groups) == 0 && len(bad) == 0 {
			return []model.Finding{{Status: model.StatusInfo, Location: loc, Observed: none}}
		}

		var lines []string
		for _, g := range groups {
			lines = append(lines, g.describe())
		}
		observed := "Content-Signal declared: " + capGroups(lines, 4)

		if len(bad) > 0 {
			return []model.Finding{{
				Status: model.StatusFail, Severity: model.SeverityWarn, Location: loc,
				Observed:     "malformed Content-Signal: " + capList(bad, 4) + "; " + observed,
				Required:     "comma-separated search|ai-input|ai-train = yes|no",
				SuggestedFix: "Use the form `Content-Signal: search=yes, ai-input=yes, ai-train=no`; unknown names and values other than yes/no are not valid signals.",
			}}
		}
		return []model.Finding{{Status: model.StatusInfo, Location: loc, Observed: observed}}
	}}
}

type signalGroup struct {
	agents  []string
	signals map[string]string // name -> yes|no
}

func (g signalGroup) describe() string {
	var declared, missing []string
	for _, n := range signalNames {
		if v, ok := g.signals[n]; ok {
			declared = append(declared, n+"="+v)
		} else {
			missing = append(missing, n)
		}
	}
	s := strings.Join(g.agents, ", ") + " — "
	if len(declared) == 0 {
		s += "no valid signals"
	} else {
		s += strings.Join(declared, ", ")
	}
	if len(missing) > 0 && len(declared) > 0 {
		s += " (" + strings.Join(missing, ", ") + ": not declared)"
	}
	return s
}

// parseContentSignals attributes each Content-Signal line to the User-agent
// group it sits in (consecutive User-agent lines, then rules) and returns the
// groups that declare at least one signal, plus every malformed token.
func parseContentSignals(body []byte) (groups []signalGroup, bad []string) {
	text := strings.TrimPrefix(string(body), "\xEF\xBB\xBF")
	var cur *signalGroup
	var curAgents []string
	sawRule := false
	flush := func() {
		if cur != nil {
			groups = append(groups, *cur)
			cur = nil
		}
	}

	for _, raw := range strings.Split(text, "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		key, val = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val)

		switch key {
		case "user-agent":
			if sawRule {
				flush()
				curAgents, sawRule = nil, false
			}
			curAgents = append(curAgents, val)
		case "content-signal":
			sawRule = true
			if cur == nil {
				cur = &signalGroup{agents: append([]string(nil), curAgents...), signals: map[string]string{}}
				if len(cur.agents) == 0 {
					cur.agents = []string{"(no User-agent)"}
				}
			}
			for _, tok := range strings.Split(val, ",") {
				tok = strings.TrimSpace(tok)
				if tok == "" {
					continue
				}
				name, value, hasEq := strings.Cut(tok, "=")
				name, value = strings.ToLower(strings.TrimSpace(name)), strings.ToLower(strings.TrimSpace(value))
				known := false
				for _, n := range signalNames {
					known = known || n == name
				}
				switch {
				case !hasEq:
					bad = append(bad, fmt.Sprintf("%q is not name=value", truncate(tok, 40)))
				case !known:
					bad = append(bad, fmt.Sprintf("unknown signal %q", truncate(name, 40)))
				case value != "yes" && value != "no":
					bad = append(bad, fmt.Sprintf("%s=%q (expected yes or no)", name, truncate(value, 40)))
				default:
					cur.signals[name] = value
				}
			}
		case "disallow", "allow":
			sawRule = true
		}
	}
	flush()
	return groups, bad
}

func capGroups(lines []string, n int) string {
	if len(lines) <= n {
		return strings.Join(lines, " | ")
	}
	return strings.Join(lines[:n], " | ") + fmt.Sprintf(" | +%d more", len(lines)-n)
}

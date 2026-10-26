package demo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// turnstileVerifyURL is a var, not a const, so tests can point it at a local
// httptest server instead of a real network call to Cloudflare.
var turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

const (
	// turnstileAction names the one surface this widget protects. The
	// frontend renders the widget with the same action, and a token minted
	// for any other action (another form, another site sharing the key) is
	// rejected even though Cloudflare itself calls it valid.
	turnstileAction = "scan"

	// Cloudflare documents tokens as at most 2048 characters; anything longer
	// isn't a token, so it's rejected without spending a siteverify call.
	maxTurnstileTokenLen = 2048

	turnstileVerifyTimeout = 10 * time.Second
)

var turnstileClient = &http.Client{Timeout: turnstileVerifyTimeout}

type turnstileVerifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Action     string   `json:"action"`
	Hostname   string   `json:"hostname"`
}

// turnstileConfig is everything server-side verification needs. hostnames is
// the allowlist of sites a token may have been solved on — required, because
// a site key can be used from any domain listed on the widget, and this
// endpoint should only honour tokens from its own page.
type turnstileConfig struct {
	secret    string
	hostnames []string
}

// verifyTurnstile checks a visitor-submitted Cloudflare Turnstile token.
// Callers only invoke this when Turnstile is configured — an empty secret
// means Turnstile is off entirely (e.g. local dev), not "always fail closed."
//
// A malformed or missing token, a rejected token, a wrong action, and a
// hostname outside the allowlist are all (false, nil): one "not human" branch
// for the caller. (false, err) is reserved for not being able to ask
// Cloudflare at all — network failure, non-200, unreadable body — which the
// caller fails closed on too, but reports differently. Replay needs no local
// state: siteverify itself rejects a token the second time it's presented.
func verifyTurnstile(ctx context.Context, cfg turnstileConfig, token, remoteIP string) (bool, error) {
	if token == "" || len(token) > maxTurnstileTokenLen || len(cfg.hostnames) == 0 {
		return false, nil
	}
	form := url.Values{"secret": {cfg.secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, turnstileVerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := turnstileClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("turnstile verify request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("turnstile verify returned HTTP %d", resp.StatusCode)
	}

	var result turnstileVerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("turnstile verify response: %w", err)
	}
	if !result.Success || result.Action != turnstileAction {
		return false, nil
	}
	for _, h := range cfg.hostnames {
		if strings.EqualFold(result.Hostname, h) {
			return true, nil
		}
	}
	return false, nil
}

// ParseHostnames splits a comma-separated hostname list (the
// TURNSTILE_HOSTNAMES / --turnstile-hostnames format), trimming blanks.
func ParseHostnames(raw string) []string {
	var out []string
	for _, h := range strings.Split(raw, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

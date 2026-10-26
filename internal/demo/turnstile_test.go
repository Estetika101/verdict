package demo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var testTurnstile = turnstileConfig{secret: "s3cr3t", hostnames: []string{"verdict.example.org"}}

func TestVerifyTurnstile_EmptyTokenFailsWithoutCallingOut(t *testing.T) {
	// No token submitted at all — must fail immediately, no network call
	// (there's no real secret/endpoint here, so a network call would error,
	// proving this path returns before attempting one).
	ok, err := verifyTurnstile(context.Background(), turnstileConfig{secret: "fake-secret", hostnames: []string{"x"}}, "", "203.0.113.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("empty token should never verify as success")
	}
}

func withMockTurnstile(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	old := turnstileVerifyURL
	turnstileVerifyURL = srv.URL
	t.Cleanup(func() { turnstileVerifyURL = old })
}

func TestVerifyTurnstile_Success(t *testing.T) {
	withMockTurnstile(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.FormValue("secret") != "s3cr3t" || r.FormValue("response") != "good-token" {
			t.Errorf("unexpected form values: secret=%q response=%q", r.FormValue("secret"), r.FormValue("response"))
		}
		json.NewEncoder(w).Encode(turnstileVerifyResponse{Success: true, Action: turnstileAction, Hostname: "verdict.example.org"})
	})
	ok, err := verifyTurnstile(context.Background(), testTurnstile, "good-token", "203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected success")
	}
}

func TestVerifyTurnstile_RejectedToken(t *testing.T) {
	withMockTurnstile(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(turnstileVerifyResponse{Success: false, ErrorCodes: []string{"invalid-input-response"}})
	})
	ok, err := verifyTurnstile(context.Background(), testTurnstile, "bad-token", "203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected failure for a rejected token")
	}
}

// A token Cloudflare accepts is still refused when it was solved for a
// different action or on a hostname outside the allowlist — the checks that
// stop a token minted elsewhere with the same site key from counting here.
func TestVerifyTurnstile_ActionAndHostnameMustMatch(t *testing.T) {
	cases := []struct {
		name             string
		action, hostname string
		want             bool
	}{
		{"match", turnstileAction, "verdict.example.org", true},
		{"hostname case-insensitive", turnstileAction, "Verdict.Example.org", true},
		{"wrong action", "login", "verdict.example.org", false},
		{"no action", "", "verdict.example.org", false},
		{"foreign hostname", turnstileAction, "evil.example.com", false},
		{"no hostname", turnstileAction, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withMockTurnstile(t, func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(turnstileVerifyResponse{Success: true, Action: tc.action, Hostname: tc.hostname})
			})
			ok, err := verifyTurnstile(context.Background(), testTurnstile, "tok", "203.0.113.5")
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.want {
				t.Errorf("got %v, want %v", ok, tc.want)
			}
		})
	}
}

// Malformed tokens and an empty allowlist are refused before any network
// call — the mock fails the test if it's reached.
func TestVerifyTurnstile_RejectsBeforeCallingOut(t *testing.T) {
	withMockTurnstile(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("siteverify should not have been called")
	})
	cases := map[string]struct {
		cfg   turnstileConfig
		token string
	}{
		"oversized token": {testTurnstile, strings.Repeat("a", maxTurnstileTokenLen+1)},
		"empty allowlist": {turnstileConfig{secret: "s3cr3t"}, "tok"},
	}
	for name, tc := range cases {
		ok, err := verifyTurnstile(context.Background(), tc.cfg, tc.token, "203.0.113.5")
		if err != nil || ok {
			t.Errorf("%s: got (%v, %v), want (false, nil)", name, ok, err)
		}
	}
}

// Cloudflare being unreachable or erroring is an error, not a verdict, so
// the caller can say "try again" instead of "you're a bot".
func TestVerifyTurnstile_NonOKIsError(t *testing.T) {
	withMockTurnstile(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream down", http.StatusInternalServerError)
	})
	ok, err := verifyTurnstile(context.Background(), testTurnstile, "tok", "203.0.113.5")
	if err == nil || ok {
		t.Errorf("got (%v, %v), want (false, error)", ok, err)
	}
}

func TestNewServer_TurnstileRequiresHostnames(t *testing.T) {
	if _, err := NewServer(Options{TurnstileSiteKey: "site", TurnstileSecretKey: "secret"}); err == nil {
		t.Error("expected an error for Turnstile keys with no hostname allowlist")
	}
	if _, err := NewServer(Options{TurnstileSiteKey: "site", TurnstileSecretKey: "secret", TurnstileHostnames: []string{"a.example"}}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseHostnames(t *testing.T) {
	got := ParseHostnames(" a.example , ,b.example,")
	if len(got) != 2 || got[0] != "a.example" || got[1] != "b.example" {
		t.Errorf("got %q", got)
	}
	if ParseHostnames("") != nil {
		t.Error("empty input should give nil")
	}
}

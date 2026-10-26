// Command server is the Vercel entrypoint for the public demo. Vercel's Go
// Framework Preset auto-detects cmd/server/main.go and runs it as a normal
// net/http server bound to $PORT — no separate per-file serverless handlers
// needed, so this reuses internal/demo.Server exactly as-is, the same code
// path exercised by `verdict demo` for self-hosted/Docker deployments.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Estetika101/verdict/internal/demo"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // local `go run ./cmd/server` without Vercel setting $PORT
	}

	var store *demo.Store
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		s, err := demo.OpenStore(ctx, dbURL)
		cancel()
		if err != nil {
			// Fail open, not closed: a demo endpoint without logging/rate
			// limiting is degraded, not broken — the same tradeoff runDemo
			// makes for the self-hosted command.
			log.Printf("server: %v (continuing without scan logging or rate limiting)", err)
		} else {
			store = s
			defer store.Close()
		}
	}

	// Vercel overwrites X-Real-IP (and X-Forwarded-For) at its edge, so a
	// visitor can't spoof either; Fly-Client-IP is NOT overwritten there and
	// must not be trusted. Override only if you front this with something
	// else that sets a different header.
	clientIPHeader := os.Getenv("CLIENT_IP_HEADER")
	if clientIPHeader == "" {
		clientIPHeader = "X-Real-IP"
	}

	srv, err := demo.NewServer(demo.Options{
		Store:              store,
		TurnstileSiteKey:   os.Getenv("TURNSTILE_SITE_KEY"),
		TurnstileSecretKey: os.Getenv("TURNSTILE_SECRET_KEY"),
		ClientIPHeader:     clientIPHeader,
	})
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	addr := fmt.Sprintf(":%s", port)
	log.Printf("server: listening on %s", addr)
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatalf("server: %v", err)
	}
}

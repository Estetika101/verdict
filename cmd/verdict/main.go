// Command verdict is an open-source, self-hostable web QA auditor.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Estetika101/verdict/internal/checks"
	"github.com/Estetika101/verdict/internal/config"
	"github.com/Estetika101/verdict/internal/dashboard"
	"github.com/Estetika101/verdict/internal/demo"
	"github.com/Estetika101/verdict/internal/engine"
	"github.com/Estetika101/verdict/internal/model"
	"github.com/Estetika101/verdict/internal/plugin"
	"github.com/Estetika101/verdict/internal/report"
)

// version is the tool's own release version, distinct from the report schema.
const version = "0.1.0-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches on the command grammar (v0.4 §4b): `audit` is the default
// verb, so a bare `verdict --config x.yaml` is an alias for `verdict audit
// --config x.yaml`. `serve` is the only other verb implemented so far.
func run(args []string, stdout, stderr *os.File) int {
	if len(args) > 0 && args[0] == "serve" {
		return runServe(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "demo" {
		return runDemo(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "audit" {
		args = args[1:]
	}
	return runAudit(args, stdout, stderr)
}

// runDemo starts the public "try it live" scan server (internal/demo) — a
// separate command from `serve`, deliberately: `serve` is the trusted local/
// LAN dashboard over your own config and reports; `demo` is the unauthenticated
// public endpoint for the marketing site, with its own hardened single-fetch
// path, rate limiting, and optional Postgres logging. Never the same process
// or code path as the config editor.
func runDemo(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("verdict demo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	host := fs.String("host", "0.0.0.0", "bind address (0.0.0.0 by default — this command is meant to be public)")
	port := fs.Int("port", 8080, "port")
	dbURL := fs.String("database-url", os.Getenv("DATABASE_URL"), "Postgres connection string for scan logging (optional; defaults to $DATABASE_URL, logging disabled if empty)")
	turnstileSiteKey := fs.String("turnstile-sitekey", os.Getenv("TURNSTILE_SITE_KEY"), "Cloudflare Turnstile site key (public; defaults to $TURNSTILE_SITE_KEY)")
	turnstileSecretKey := fs.String("turnstile-secret", os.Getenv("TURNSTILE_SECRET_KEY"), "Cloudflare Turnstile secret key (private; defaults to $TURNSTILE_SECRET_KEY; verification is skipped entirely if either key is empty)")
	clientIPHeader := fs.String("client-ip-header", os.Getenv("CLIENT_IP_HEADER"), "request header carrying the visitor's IP, trusted for rate limiting (defaults to $CLIENT_IP_HEADER): \"Fly-Client-IP\" on Fly, \"X-Real-IP\" on Vercel, empty when exposed directly (uses the connection address)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var store *demo.Store
	if *dbURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		s, err := demo.OpenStore(ctx, *dbURL)
		cancel()
		if err != nil {
			fmt.Fprintf(stderr, "verdict: demo: %v (continuing without scan logging)\n", err)
		} else {
			store = s
			defer store.Close()
			fmt.Fprintln(stdout, "verdict: scan logging enabled")
		}
	} else {
		fmt.Fprintln(stdout, "verdict: no --database-url / $DATABASE_URL set — scan logging disabled")
	}

	if *turnstileSiteKey != "" && *turnstileSecretKey != "" {
		fmt.Fprintln(stdout, "verdict: Cloudflare Turnstile human verification enabled")
	} else {
		fmt.Fprintln(stdout, "verdict: no Turnstile site+secret key set — human verification disabled")
	}

	srv, err := demo.NewServer(demo.Options{
		Store:              store,
		TurnstileSiteKey:   *turnstileSiteKey,
		TurnstileSecretKey: *turnstileSecretKey,
		ClientIPHeader:     *clientIPHeader,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	addr := fmt.Sprintf("%s:%d", *host, *port)
	fmt.Fprintf(stdout, "verdict: public demo listening on http://%s\n", addr)
	if err := http.ListenAndServe(addr, srv); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}

// runOnce executes one full audit pass against cfg: filters built-in and
// plugin checks by config, crawls every configured site, and returns the
// assembled report. Shared between the CLI's own audit run and the
// dashboard's "run audit now" trigger, so there is exactly one audit
// execution path, not two that could drift.
func runOnce(ctx context.Context, cfg *config.Config) (model.Report, error) {
	var enabled []model.Check
	for _, c := range checks.Builtins() {
		m := c.Meta()
		if cfg.CheckEnabled(m.Module, m.ID) {
			enabled = append(enabled, c)
		}
	}

	for _, path := range cfg.Plugins {
		p, perr := plugin.Load(ctx, path)
		if perr != nil {
			return model.Report{}, fmt.Errorf("plugin %s: %w", path, perr)
		}
		defer p.Close(ctx)
		m := p.Meta()
		if cfg.CheckEnabled(m.Module, m.ID) {
			enabled = append(enabled, p)
		}
	}

	rep := model.Report{
		SchemaVersion: "1.0.0-draft",
		Tool:          model.ToolInfo{Name: "verdict", Version: version},
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	// Sites run sequentially in the slice (siteConcurrency > 1 is future work).
	for _, site := range cfg.Sites {
		sr, rerr := engine.RunSite(ctx, cfg.Crawl, engine.SiteTarget{
			Name:       site.Name,
			URL:        site.URL,
			CrawlLimit: site.CrawlLimit,
		}, enabled, cfg.CheckConfig())
		if rerr != nil {
			return model.Report{}, fmt.Errorf("%s: %w", site.URL, rerr)
		}
		rep.Sites = append(rep.Sites, sr)
	}
	return rep, nil
}

func runAudit(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("verdict audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "verdict.yaml", "path to the config file")
	outDir := fs.String("out", "", "override output.outDir")
	serve := fs.Bool("serve", false, "after auditing, start the local dashboard on the result")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *outDir != "" {
		// An explicit --out is a shell-typed flag, resolved relative to the
		// invoking shell's cwd like any other CLI argument — left as-is.
		cfg.Output.OutDir = *outDir
	} else {
		// A relative outDir that came FROM the config file anchors to the
		// config file's own directory, not whatever cwd verdict happens to run
		// from — see resolveOutDir's doc comment.
		cfg.Output.OutDir = resolveOutDir(*configPath, cfg.Output.OutDir)
	}

	ctx := context.Background()
	rep, rerr := runOnce(ctx, cfg)
	if rerr != nil {
		fmt.Fprintf(stderr, "verdict: %v\n", rerr)
		return 2
	}

	formats := cfg.Output.Formats
	if *serve && !contains(formats, "json") {
		// The dashboard reads report.json; --serve without a json format
		// configured would otherwise start a server with nothing to show.
		formats = append(append([]string{}, formats...), "json")
	}
	if err := report.Emit(rep, formats, cfg.Output.OutDir, stdout, isTerminal(stdout)); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	code := report.ExitCode(rep, cfg.FailOn)
	if !*serve {
		return code
	}

	addr := fmt.Sprintf("%s:%d", cfg.Serve.Host, cfg.Serve.Port)
	fmt.Fprintf(stdout, "verdict: exit code would be %d; serving results at http://%s (Ctrl+C to stop)\n", code, addr)
	opts := dashboardOptions(*configPath, cfg.Output.OutDir, cfg.Serve.AllowRemoteConfig)
	if err := dashboard.ListenAndServe(addr, opts); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// runServe starts the dashboard against an already-written report directory.
// --report wins if both --config and --report are given; otherwise the
// directory is derived from --config's output.outDir, defaulting to
// ./verdict-report. When --config is given, the dashboard also gets a working
// config editor and "run audit now" trigger (each fresh-loading cfg from
// configPath, so a saved edit takes effect on the next triggered run).
func runServe(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("verdict serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "config file to derive the report directory and bind address from, and to enable the config editor + audit trigger")
	reportDir := fs.String("report", "", "directory containing report.json (default: ./verdict-report, or output.outDir from --config)")
	host := fs.String("host", "", "bind address (default 127.0.0.1, or serve.host from --config)")
	port := fs.Int("port", 0, "port (default 8787, or serve.port from --config)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	dir := *reportDir
	bindHost, bindPort := "127.0.0.1", 8787
	allowRemoteConfig := false

	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		if dir == "" {
			dir = resolveOutDir(*configPath, cfg.Output.OutDir)
		}
		bindHost, bindPort = cfg.Serve.Host, cfg.Serve.Port
		allowRemoteConfig = cfg.Serve.AllowRemoteConfig
	}
	if dir == "" {
		dir = "./verdict-report"
	}
	if *host != "" {
		bindHost = *host
	}
	if *port != 0 {
		bindPort = *port
	}

	addr := fmt.Sprintf("%s:%d", bindHost, bindPort)
	if *configPath == "" {
		fmt.Fprintf(stdout, "verdict: serving %s at http://%s (view-only — no --config given, so config editing and the audit trigger are disabled; Ctrl+C to stop)\n", dir, addr)
	} else {
		fmt.Fprintf(stdout, "verdict: serving %s at http://%s (Ctrl+C to stop)\n", dir, addr)
	}
	opts := dashboardOptions(*configPath, dir, allowRemoteConfig)
	if err := dashboard.ListenAndServe(addr, opts); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}

// dashboardOptions wires the audit-trigger callback to a fresh config.Load +
// runOnce each time it's invoked, so a config edit saved through the
// dashboard's editor takes effect on the very next triggered run without
// restarting the server.
func dashboardOptions(configPath, reportDir string, allowRemoteConfig bool) dashboard.Options {
	opts := dashboard.Options{ReportDir: reportDir, AllowRemoteConfig: allowRemoteConfig}
	if configPath == "" {
		return opts
	}
	opts.ConfigPath = configPath
	opts.RunAudit = func() error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		ctx := context.Background()
		rep, err := runOnce(ctx, cfg)
		if err != nil {
			return err
		}
		formats := cfg.Output.Formats
		if !contains(formats, "json") {
			formats = append(append([]string{}, formats...), "json")
		}
		return report.Emit(rep, formats, resolveOutDir(configPath, cfg.Output.OutDir), os.Stdout, false)
	}
	return opts
}

// resolveOutDir anchors a relative output.outDir to the CONFIG FILE'S
// directory, not the process's current working directory. Without this, a
// dashboard-triggered audit (cwd is whatever the server happened to start
// with — invisible to whoever clicked the button in a browser) can silently
// write its report somewhere other than where the dashboard is reading from,
// leaving the Report tab stuck showing a stale run forever. An absolute
// outDir is left untouched.
func resolveOutDir(configPath, outDir string) string {
	if filepath.IsAbs(outDir) || configPath == "" {
		return outDir
	}
	return filepath.Join(filepath.Dir(configPath), outDir)
}

// isTerminal reports whether w is an interactive terminal and color is allowed.
func isTerminal(w *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	info, err := w.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

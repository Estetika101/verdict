# Verdict

**An open-source, self-hostable web QA auditor.** Verdict checks any HTTP-reachable
site for SEO, GEO (generative-engine optimization), accessibility, performance,
security headers, broken links, and structured data — with no mandatory API
keys, no cloud dependency, and no mandatory headless browser. It ships as a
single static Go binary, so it runs anywhere from a Raspberry Pi to a CI runner.

> **Status: walking skeleton complete; runnable.** Verdict is being built from a
> detailed spec (`webqa-SPEC-v4.md`, canonical). The first vertical slice — which
> proves every load-bearing architectural seam at once — is done: the polite
> fetch engine (per-host politeness, robots, per-run cache, fetch budget), the
> `security-headers` (page) and `broken-links` (site) checks, content-hash
> finding IDs, the fail/pass/skipped/info model, console/JSON/Markdown/tasks
> output with a CI exit gate, and a **sandboxed WebAssembly plugin runtime** with
> a byte-exact golden test and a 14-case acceptance suite (green under `-race`).
> So `verdict --config verdict.yaml` produces a real audit of a live site today.
>
> Since the slice: the full **SEO module** (16 checks — on-page, social, sitemap,
> hreflang reciprocity, duplicate-content) landed, a **local browser dashboard**
> (`verdict serve`) now renders any report interactively — including a **Config
> tab** to add/remove sites, toggle checks, and trigger a fresh audit without
> touching YAML by hand — and the **GEO module** landed: AI-crawler posture
> (grouped by vendor and by purpose — training / search / user-fetch, not just
> a flat allow/block), `llms.txt` structural validation against the actual
> (tiny) spec, and publish/modified-date presence + measured age. GEO
> deliberately reports facts, not judgments — see the module's doc comment for
> why a staleness *threshold* is a different, paid-tier-shaped feature.
>
> Still to come: accessibility / structured-data modules, Tier 2
> (Chromium — Core Web Vitals + rendered a11y), `watch`/`init`, comment-preserving
> config writes, local run-over-run diff, and multi-site concurrency.
>
> There's also now a **public demo mode** (`verdict demo`) — a separate,
> unauthenticated "paste a URL, get an instant scan" endpoint for the marketing
> site, intentionally not built on the same code path as the trusted local
> dashboard. See "Public demo mode" below before exposing it anywhere.

## Public demo mode

`verdict demo` runs a single-page, rate-limited, SSRF-hardened scan endpoint
meant for public/marketing use — genuinely different from `verdict serve`, not
just a flag on it:

- **One fetch, hardened at dial time, not just at URL-check time.** The
  target's IP is validated both before connecting and again via a custom
  `DialContext` at the moment a connection actually opens — closing the
  DNS-rebinding gap where a hostname resolves to a public IP when checked and
  a private one moments later. Every redirect hop is re-validated the same way.
  Rejects loopback/private/link-local/multicast ranges (including the cloud
  metadata address, `169.254.169.254`).
- **No config editing, no Fetch capability for checks, no crawling.** Only
  page-scoped checks run (filtered by `Meta().Scope`, not a hand-maintained ID
  list), and the demo's `CheckContext.Fetch` always errors — nothing a check
  does can trigger a second network call.
- **Rate-limited** (5 scans/hour/IP by default) and **optionally logs to
  Postgres** (`--database-url`, or `$DATABASE_URL`; a hashed IP, hostname, and
  finding counts only — no scraped content, no plaintext IP) purely for
  operator visibility into what's being scanned. Logging is disabled, not
  fatal, if no database is configured. Rate limiting is a `COUNT` query
  against that same log table, deliberately not an in-memory counter — an
  in-process map can't guarantee a given visitor's requests land on the same
  warm instance on any elastic/serverless host, so it would silently stop
  limiting anything the moment that assumption breaks. This also means rate
  limiting is only active when a database is configured.
- **Optional Cloudflare Turnstile human verification** (`--turnstile-sitekey`
  / `--turnstile-secret`, or `$TURNSTILE_SITE_KEY` / `$TURNSTILE_SECRET_KEY`).
  Off unless BOTH keys are set — a site key alone would render a widget
  nothing actually checks. The widget loads dynamically (the frontend fetches
  `/api/turnstile-sitekey` and only injects Cloudflare's script if a key comes
  back), so a deploy without Turnstile configured behaves exactly as if this
  feature didn't exist.
- **Client IP comes from one trusted header, or none.** By default the rate
  limiter keys on the connection's address only. Behind a proxy, set
  `--client-ip-header` (or `$CLIENT_IP_HEADER`) to the single header your edge
  overwrites on every request: `Fly-Client-IP` on Fly, `X-Real-IP` on Vercel,
  empty when exposed directly. Any other header is ignored, because trusting
  one the platform doesn't overwrite lets a visitor pick a fresh rate-limit
  key per request.

```sh
verdict demo --port 8080 \
  --database-url "postgres://…" \
  --client-ip-header "Fly-Client-IP" \
  --turnstile-sitekey "0x4..." --turnstile-secret "0x4..."
```

`Dockerfile.demo` builds a dedicated image for this — deliberately separate
from the main `Dockerfile`, so the public-facing process can never accidentally
ship with the dashboard's config-editing surface reachable. This is the
self-host path (Fly, a VPS, any container host).

**Deploying to Vercel** is the other option, and needs no separate Dockerfile:
`cmd/server/main.go` is a second, minimal entrypoint that builds the exact
same `internal/demo.Server` from environment variables instead of flags
(`DATABASE_URL`, `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY`, `PORT`,
`CLIENT_IP_HEADER`, which defaults to `X-Real-IP` there) —
Vercel's Go Framework Preset auto-detects it, so `vercel.json` only needs
`"framework": "go"`. Point `DATABASE_URL` at Neon and it's the same
Postgres-backed logging/rate-limiting as the self-hosted command, just on a
platform that doesn't guarantee a warm process sticks around between
requests (which is exactly why the rate limiter is a query against the log
table rather than in-memory state — see above).

## Quick start

```sh
go build -o verdict ./cmd/verdict
./verdict audit --config slice.yaml     # audits the configured site(s)
./verdict serve --report ./verdict-report # view the results at http://127.0.0.1:8787
```

`verdict audit --config x.yaml --serve` does both in one step — audits, then
immediately opens the dashboard on the result. A bare `verdict --config x.yaml`
(no verb) is shorthand for `verdict audit --config x.yaml`.

Exit code is non-zero when a finding at or above `failOn` is present, so it
drops straight into CI.

## What makes it different

- **Honest reporting.** Every result is `pass` / `fail` / `skipped` / `info`,
  and a skipped check is a visible line, never silent — a clean report is not a
  false green. WCAG findings map to specific success criteria and separate what
  a robot can verify from what needs a human.
- **Agent-facing output.** Alongside console/Markdown/JSON, Verdict emits a
  `verdict-tasks.md` checklist purpose-built to hand to a coding assistant, derived
  from the same findings so it never drifts.
- **Well-behaved crawler.** Respects `robots.txt` by default, rate-limits per
  host, and reports a WAF challenge as `blocked` rather than mislabeling it
  "site down."
- **Sandboxed plugins.** Third-party checks are WebAssembly modules with no
  ambient authority — a plugin reaches the network only through the engine's own
  polite, budgeted fetch path. Point `plugins:` at a `.wasm` file in config; it
  runs alongside the built-ins through the identical check interface. A runaway
  plugin is interrupted and recorded as skipped, never allowed to hang the run.
  See `plugins/example-x-powered-by/` for a TinyGo example.

## Local dashboard

`verdict serve` starts a read-only, localhost-only web UI (`http://127.0.0.1:8787`
by default) over whatever `report.json` is already on disk — same embedded
single binary, no database, no external calls. It's a viewer, not a second
place data lives: everything it shows is derived from the same JSON the
console/tasks/markdown formats read.

```sh
verdict serve --report ./verdict-report        # view-only: no --config, so editing/triggering is disabled
verdict serve --config verdict.yaml            # view + a Config tab (sites/checks/output) + "run audit now"
verdict audit --config verdict.yaml --serve    # audit once, then open the dashboard on the result
```

The Config tab's Save writes straight to the config file (merged onto whatever
else is already there — crawl/tier2/plugins/serve settings not shown in the
form are left untouched, never blanked out) and validates through the exact
same rules the CLI enforces on a hand-edited file. **Known gap:** it does not
yet preserve comments or key order in a hand-written YAML file — saving from
the form will flatten those. Its config-writing and audit-triggering endpoints
are localhost-only regardless of `--host`, unless `serve.allowRemoteConfig` is
explicitly set — viewing a report over the LAN is one risk tier, letting
anyone on the LAN repoint your crawler is a different, higher one.

Running it directly in a terminal (or via a coding assistant's background-task
runner) ties its lifetime to that session — close the terminal or end the
session and the server dies. To keep it running independently on macOS, use a
`launchd` agent (survives terminal/session closure, restarts on login):

```sh
# ~/Library/LaunchAgents/org.<you>.verdict-dashboard.plist — RunAtLoad, no KeepAlive
# (so it's always up, but launchctl stop actually stops it rather than
# launchd immediately restarting it)
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.<you>.verdict-dashboard.plist
launchctl stop org.<you>.verdict-dashboard     # stop it manually
launchctl kickstart gui/$(id -u)/org.<you>.verdict-dashboard   # start it again
```

On the Pi, a `systemd` unit is the equivalent (`WantedBy=multi-user.target`,
no `Restart=` if you want the same "stays stopped when you stop it" behavior).

## Two-tier design

- **Tier 1 (core):** HTTP + HTML parsing only. Runs anywhere the binary runs.
- **Tier 2 (optional):** activates only if Chromium is present, adding Core Web
  Vitals and rendered-DOM accessibility checks. Absent → those checks report
  `skipped`, never a failure.

## Build

Requires Go 1.25+.

```sh
go build ./cmd/verdict
go test ./...
```

## License

[MIT](LICENSE) © Peter van Aller. Verdict's auditor and every check module are
free forever; any future hosted/paid product is a separate platform *around* the
auditor, never a paywall over an existing check.

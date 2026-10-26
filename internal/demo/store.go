package demo

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Store logs demo scan activity to Postgres (Neon in production) — purely for
// operator visibility into "what's being scanned," not a user-facing feature.
// No accounts, no per-user history: that's the real Phase 1 product, not this.
type Store struct {
	db *sql.DB
}

// OpenStore connects and ensures the schema exists.
func OpenStore(ctx context.Context, connStr string) (*Store, error) {
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return nil, fmt.Errorf("demo: open db: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("demo: ping db: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS scan_log (
	id             BIGSERIAL PRIMARY KEY,
	requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	hostname       TEXT NOT NULL,
	error_count    INT,
	warn_count     INT,
	pass_count     INT,
	skip_count     INT,
	info_count     INT,
	remote_ip_hash TEXT,
	error          TEXT
)`)
	if err != nil {
		return fmt.Errorf("demo: migrate: %w", err)
	}
	// Reserve counts by (ip hash, time) on every request, so this index is
	// load-bearing for latency, not just a nice-to-have.
	_, err = s.db.ExecContext(ctx, `
CREATE INDEX IF NOT EXISTS scan_log_ip_time_idx ON scan_log (remote_ip_hash, requested_at)`)
	if err != nil {
		return fmt.Errorf("demo: migrate (index): %w", err)
	}
	return nil
}

// pendingMarker is the error value a reserved row carries between Reserve and
// Finish. A row stuck on it (the process died mid-scan) still counts toward
// the visitor's limit, which is the right outcome — and is itself a useful
// operator signal that a scan never completed.
const pendingMarker = "pending"

// ScanLogEntry is the outcome Finish writes onto a reserved row: either a
// successful scan (counts populated, Err empty) or a failed/rejected attempt
// (Err populated) — both are useful signal for "what's being scanned,"
// including abuse attempts. ErrorCount and WarnCount are the two severities
// within status:fail, computed by the caller from the findings themselves —
// model.Summary only has one coarse "Fail" bucket, which would misrepresent
// "9 warnings, 1 real error" as "10 failed" in the log the same way it
// briefly did in the dashboard.
type ScanLogEntry struct {
	ErrorCount, WarnCount, PassCount, SkipCount, InfoCount int
	Err                                                    string
}

// Reserve is the rate limiter: it atomically decides whether remoteIP may
// start another scan and, if so, claims the slot by inserting the row the scan
// will later fill in via Finish.
//
// Count-then-scan-then-log was a race: a scan takes seconds, so N concurrent
// requests all read the same count, all passed, and all logged afterwards —
// the limit bounded sequential traffic only. Here the check and the claim are
// one transaction, serialised per visitor by a transaction-scoped advisory
// lock on the IP hash: a second request for the same IP blocks on the lock
// until the first commits, then sees its row and counts it. Different IPs hash
// to different lock keys and never wait on each other (a hash collision just
// serialises two visitors briefly; it can't mis-count, since the count is by
// the hash column, not the lock). The lock releases on commit or rollback, so
// it can't leak. Postgres-backed rather than in-memory for the same reason as
// before: correct on any elastic/serverless host where successive requests
// don't share a process.
//
// Reserved rows count whether or not the scan later succeeds, and a request
// rejected for being over the limit inserts nothing — logging every throttled
// hit would be a cheap way to make this endpoint do more work under abuse.
func (s *Store) Reserve(ctx context.Context, remoteIP, hostname string, window time.Duration, limit int) (id int64, allowed bool, err error) {
	ipHash := hashIP(remoteIP)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("demo: reserve: begin: %w", err)
	}
	defer tx.Rollback() // no-op after Commit

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, ipHash); err != nil {
		return 0, false, fmt.Errorf("demo: reserve: lock: %w", err)
	}
	var n int
	if err := tx.QueryRowContext(ctx, `
SELECT count(*) FROM scan_log WHERE remote_ip_hash = $1 AND requested_at > $2`,
		ipHash, time.Now().Add(-window)).Scan(&n); err != nil {
		return 0, false, fmt.Errorf("demo: reserve: count: %w", err)
	}
	if n >= limit {
		return 0, false, nil // deferred Rollback releases the lock
	}
	if err := tx.QueryRowContext(ctx, `
INSERT INTO scan_log (hostname, remote_ip_hash, error) VALUES ($1, $2, $3) RETURNING id`,
		hostname, ipHash, pendingMarker).Scan(&id); err != nil {
		return 0, false, fmt.Errorf("demo: reserve: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("demo: reserve: commit: %w", err)
	}
	return id, true, nil
}

// Finish writes a scan's outcome onto the row Reserve created, replacing the
// pending marker: the error column is NULL on success and the failure reason
// otherwise. Errors are the caller's to decide whether to surface — a logging
// failure should never block the actual scan response.
func (s *Store) Finish(ctx context.Context, id int64, e ScanLogEntry) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE scan_log
SET error_count = $2, warn_count = $3, pass_count = $4, skip_count = $5, info_count = $6, error = $7
WHERE id = $1`,
		id, e.ErrorCount, e.WarnCount, e.PassCount, e.SkipCount, e.InfoCount, nullIfEmpty(e.Err))
	if err != nil {
		return fmt.Errorf("demo: finish scan: %w", err)
	}
	return nil
}

// hashIP truncates a SHA-256 of the client IP rather than storing it raw —
// enough to notice "this is the same repeat visitor" without keeping a
// plainly-identifying address around indefinitely in a log table.
func hashIP(ip string) string {
	if ip == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:])[:16]
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

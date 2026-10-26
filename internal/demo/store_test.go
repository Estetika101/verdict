package demo

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testStore opens a Store against a real local Postgres instance for
// integration testing. Skips (not fails) if VERDICT_TEST_DATABASE_URL isn't
// set, so `go test ./...` stays hermetic for anyone without Postgres
// available — Reserve's actual SQL correctness matters enough to verify
// against a real database at least once, though, not just assume the query
// is right.
func testStore(t *testing.T) *Store {
	t.Helper()
	connStr := os.Getenv("VERDICT_TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("VERDICT_TEST_DATABASE_URL not set — skipping Postgres integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := OpenStore(ctx, connStr)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	// Each test gets a clean table — this package's whole log is disposable
	// test data, never anything worth preserving between runs.
	if _, err := s.db.ExecContext(ctx, "TRUNCATE scan_log"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStore_Reserve_EnforcesLimitPerIP(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		id, ok, err := s.Reserve(ctx, "203.0.113.5", "example.com", time.Hour, 3)
		if err != nil || !ok || id == 0 {
			t.Fatalf("Reserve #%d = (%d, %v, %v), want an allowed reservation", i+1, id, ok, err)
		}
	}
	id, ok, err := s.Reserve(ctx, "203.0.113.5", "example.com", time.Hour, 3)
	if err != nil {
		t.Fatal(err)
	}
	if ok || id != 0 {
		t.Errorf("4th Reserve = (%d, %v), want denied", id, ok)
	}

	// A different IP has its own budget.
	if _, ok, err := s.Reserve(ctx, "203.0.113.9", "example.com", time.Hour, 3); err != nil || !ok {
		t.Errorf("other IP Reserve = (%v, %v), want allowed", ok, err)
	}

	// A denied attempt must not insert a row.
	var n int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM scan_log").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("scan_log has %d rows, want 4 (3 + 1 for the other IP; the denied attempt logs nothing)", n)
	}
}

func TestStore_Reserve_WindowExpiry(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if _, ok, err := s.Reserve(ctx, "203.0.113.7", "example.com", time.Hour, 1); err != nil || !ok {
		t.Fatalf("first Reserve = (%v, %v), want allowed", ok, err)
	}
	if _, ok, _ := s.Reserve(ctx, "203.0.113.7", "example.com", time.Hour, 1); ok {
		t.Fatal("second Reserve within the window should be denied at limit 1")
	}

	// Backdate the row to simulate it having aged out of the window, rather
	// than sleeping in the test.
	if _, err := s.db.ExecContext(ctx, `UPDATE scan_log SET requested_at = now() - interval '2 hours'`); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Reserve(ctx, "203.0.113.7", "example.com", time.Hour, 1); err != nil || !ok {
		t.Errorf("Reserve after backdating = (%v, %v), want allowed (entry aged out)", ok, err)
	}
}

// The regression this whole API exists for: N concurrent requests from one IP
// used to all see the same count and all pass. With the advisory lock exactly
// `limit` of them may win.
func TestStore_Reserve_ConcurrentRespectsLimit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	const goroutines, limit = 10, 5

	var wg sync.WaitGroup
	var allowed atomic.Int32
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := s.Reserve(ctx, "203.0.113.50", "example.com", time.Hour, limit)
			if err != nil {
				errs <- err
				return
			}
			if ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("Reserve: %v", err)
	}
	if got := allowed.Load(); got != limit {
		t.Errorf("%d of %d concurrent Reserves allowed, want exactly %d", got, goroutines, limit)
	}
}

// The concurrent test above can pass by luck on a fast local database, since
// the count and insert may never interleave. This one is deterministic: hold
// the per-IP advisory lock from a second transaction and check that Reserve
// for that IP waits for it, while Reserve for another IP does not.
func TestStore_Reserve_BlocksOnPerIPLock(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	const ip = "203.0.113.60"

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, hashIP(ip)); err != nil {
		t.Fatal(err)
	}

	done := make(chan bool, 1)
	go func() {
		_, ok, _ := s.Reserve(ctx, ip, "example.com", time.Hour, 5)
		done <- ok
	}()
	select {
	case <-done:
		t.Fatal("Reserve returned while the per-IP lock was held; it must wait")
	case <-time.After(300 * time.Millisecond):
	}

	if _, ok, err := s.Reserve(ctx, "203.0.113.61", "example.com", time.Hour, 5); err != nil || !ok {
		t.Errorf("Reserve for a different IP = (%v, %v), want it unblocked", ok, err)
	}

	tx.Rollback() // release the lock
	select {
	case ok := <-done:
		if !ok {
			t.Error("blocked Reserve should be allowed once the lock is released")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Reserve never proceeded after the lock was released")
	}
}

func TestStore_Reserve_InsertsPendingRow(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	id, ok, err := s.Reserve(ctx, "203.0.113.11", "evil.example", time.Hour, 5)
	if err != nil || !ok {
		t.Fatalf("Reserve = (%v, %v)", ok, err)
	}
	var host, errText string
	if err := s.db.QueryRowContext(ctx, "SELECT hostname, error FROM scan_log WHERE id = $1", id).Scan(&host, &errText); err != nil {
		t.Fatal(err)
	}
	if host != "evil.example" || errText != pendingMarker {
		t.Errorf("reserved row = (%q, %q), want (evil.example, %q)", host, errText, pendingMarker)
	}
}

func TestStore_Finish_Success(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	id, _, err := s.Reserve(ctx, "203.0.113.12", "example.com", time.Hour, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(ctx, id, ScanLogEntry{ErrorCount: 1, WarnCount: 2, PassCount: 3, SkipCount: 4, InfoCount: 5}); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	var e, w, p, sk, in int
	var errText sql.NullString
	if err := s.db.QueryRowContext(ctx,
		"SELECT error_count, warn_count, pass_count, skip_count, info_count, error FROM scan_log WHERE id = $1", id,
	).Scan(&e, &w, &p, &sk, &in, &errText); err != nil {
		t.Fatal(err)
	}
	if e != 1 || w != 2 || p != 3 || sk != 4 || in != 5 {
		t.Errorf("counts = %d/%d/%d/%d/%d, want 1/2/3/4/5", e, w, p, sk, in)
	}
	if errText.Valid {
		t.Errorf("error = %q, want NULL on success", errText.String)
	}
}

func TestStore_Finish_FailedAttemptRecorded(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	id, _, err := s.Reserve(ctx, "203.0.113.13", "evil.example", time.Hour, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(ctx, id, ScanLogEntry{Err: "private IP rejected"}); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	var errText string
	if err := s.db.QueryRowContext(ctx, "SELECT error FROM scan_log WHERE id = $1", id).Scan(&errText); err != nil {
		t.Fatal(err)
	}
	if errText != "private IP rejected" {
		t.Errorf("error column = %q, want the logged failure reason", errText)
	}
}

func TestStore_MigrateIsIdempotent(t *testing.T) {
	connStr := os.Getenv("VERDICT_TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("VERDICT_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	// OpenStore runs migrate() internally; opening twice must not error even
	// though the table/index already exist (CREATE ... IF NOT EXISTS).
	s1, err := OpenStore(ctx, connStr)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	s2, err := OpenStore(ctx, connStr)
	if err != nil {
		t.Fatalf("second OpenStore (re-migrate) failed: %v", err)
	}
	s2.Close()
}

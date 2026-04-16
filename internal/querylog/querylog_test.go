package querylog

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGetStatsReportsRollingQPS(t *testing.T) {
	logger := NewQueryLogger(true, 10, 1, "", false)
	now := time.Now()

	logger.AddLog(&LogEntry{Time: now.Add(-12 * time.Second)})
	logger.AddLog(&LogEntry{Time: now.Add(-3 * time.Second)})
	logger.AddLog(&LogEntry{Time: now.Add(-2 * time.Second)})
	logger.AddLog(&LogEntry{Time: now.Add(-1 * time.Second)})

	stats := logger.GetStats()

	if stats.TotalQueries != 4 {
		t.Fatalf("expected 4 total queries, got %d", stats.TotalQueries)
	}

	if math.Abs(stats.QPS-0.3) > 0.05 {
		t.Fatalf("expected QPS close to 0.3, got %.3f", stats.QPS)
	}
}

func TestDisabledLoggerDropsLogs(t *testing.T) {
	logger := NewQueryLogger(false, 10, 1, "", false)

	logger.AddLog(&LogEntry{
		ClientIP: "127.0.0.1",
		Domain:   "example.com.",
		Upstream: "Rule(CN)",
		Status:   "NOERROR",
	})

	stats := logger.GetStats()
	if stats.TotalQueries != 0 {
		t.Fatalf("expected disabled logger to ignore queries, got %d", stats.TotalQueries)
	}

	logs, total := logger.GetLogs(0, 10, "")
	if len(logs) != 0 || total != 0 {
		t.Fatalf("expected disabled logger to return no logs, got len=%d total=%d", len(logs), total)
	}
}

func TestTopStatsTrackBoundedHistory(t *testing.T) {
	logger := NewQueryLogger(true, 2, 1, "", false)

	logger.AddLog(&LogEntry{ClientIP: "1.1.1.1", Domain: "first.example", Upstream: "Rule(CN)"})
	logger.AddLog(&LogEntry{ClientIP: "2.2.2.2", Domain: "second.example", Upstream: "Rule(CN)"})
	logger.AddLog(&LogEntry{ClientIP: "3.3.3.3", Domain: "third.example", Upstream: "Rule(Overseas)"})

	stats := logger.GetStats()
	if stats.TotalQueries != 3 {
		t.Fatalf("expected total queries to keep lifetime count, got %d", stats.TotalQueries)
	}
	if _, ok := stats.TopDomains["first.example"]; ok {
		t.Fatalf("expected evicted domain to be removed from bounded top stats")
	}
	if len(stats.TopDomains) != 2 {
		t.Fatalf("expected top domain stats to match bounded history, got %d entries", len(stats.TopDomains))
	}

	logs, total := logger.GetLogs(0, 10, "")
	if total != 2 {
		t.Fatalf("expected in-memory log history to be capped at 2, got %d", total)
	}
	if len(logs) != 2 || logs[0].Domain != "third.example" || logs[1].Domain != "second.example" {
		t.Fatalf("unexpected bounded log order: %#v", logs)
	}
}

func TestSaveToFileUsesBoundedWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	before := runtime.NumGoroutine()

	logger := NewQueryLogger(true, 32, 10, path, true)
	t.Cleanup(func() {
		if err := logger.Close(); err != nil {
			t.Fatalf("close logger: %v", err)
		}
	})

	for i := 0; i < 2000; i++ {
		logger.AddLog(&LogEntry{
			ClientIP: "127.0.0.1",
			Domain:   "example.com",
			Upstream: "Rule(CN)",
			Status:   "NOERROR",
		})
	}

	after := runtime.NumGoroutine()
	if delta := after - before; delta > 20 {
		t.Fatalf("expected bounded writer goroutines, got delta=%d (before=%d after=%d)", delta, before, after)
	}
}

func TestCloseFlushesQueuedLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query.log")
	logger := NewQueryLogger(true, 32, 10, path, true)

	for i := 0; i < 50; i++ {
		logger.AddLog(&LogEntry{
			ClientIP: "127.0.0.1",
			Domain:   "flush.example",
			Upstream: "Rule(CN)",
			Status:   "NOERROR",
		})
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}

	if lines := strings.Count(string(data), "\n"); lines != 50 {
		t.Fatalf("expected 50 persisted lines, got %d", lines)
	}
}

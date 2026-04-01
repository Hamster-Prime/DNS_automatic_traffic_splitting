package querylog

import (
	"math"
	"testing"
	"time"
)

func TestGetStatsReportsRollingQPS(t *testing.T) {
	logger := NewQueryLogger(1, "", false)
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

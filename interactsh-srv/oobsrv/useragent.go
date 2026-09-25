package oobsrv

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// uaCheckInterval is how often the report loop checks flush triggers.
const uaCheckInterval = 30 * time.Second

// uaReportThreshold is how many distinct user agents trigger a report and clear.
const uaReportThreshold = 100

// userAgentTracker tallies distinct User-Agent strings from registration
// events and periodically reports then clears them. Lock-free writes: a
// sync.Map of per-key atomic counters, plus an atomic.Pointer swap on flush.
// A record racing a flush may land in either window or be dropped.
type userAgentTracker struct {
	logger     *slog.Logger
	threshold  int64 // report once this many distinct agents accumulate
	checkEvery time.Duration
	stop       chan struct{}
	closeOnce  sync.Once

	active      atomic.Pointer[sync.Map] // map[string]*atomic.Uint64
	windowStart atomic.Int64             // unix nanos when the open report window began
}

func newUserAgentTracker(logger *slog.Logger, threshold int64, checkEvery time.Duration) *userAgentTracker {
	t := &userAgentTracker{
		logger:     logger,
		threshold:  threshold,
		checkEvery: checkEvery,
		stop:       make(chan struct{}),
	}
	t.windowStart.Store(time.Now().UnixNano())
	t.active.Store(&sync.Map{})
	return t
}

// record tallies one registration for ua, labeling absent headers as empty.
func (t *userAgentTracker) record(ua string) {
	if ua == "" {
		ua = "<empty>" // label absent headers so they still appear in reports
	}
	counter, _ := t.active.Load().LoadOrStore(ua, &atomic.Uint64{})
	counter.(*atomic.Uint64).Add(1)
}

// flush swaps out the active map for a fresh one and returns per-agent counts
// plus the total registration tally from the closed window.
func (t *userAgentTracker) flush() (map[string]uint64, uint64) {
	old := t.active.Swap(&sync.Map{})

	counts := make(map[string]uint64)
	var total uint64
	old.Range(func(k, v any) bool {
		c := v.(*atomic.Uint64).Load()
		counts[k.(string)] = c
		total += c
		return true
	})
	return counts, total
}

func (t *userAgentTracker) Name() string { return "user-agent-report" }

// Start runs the report loop until ctx is cancelled or Close is called.
func (t *userAgentTracker) Start(ctx context.Context) error {
	go t.run(ctx)
	return nil
}

func (t *userAgentTracker) Close() error {
	t.closeOnce.Do(func() { close(t.stop) })
	return nil
}

func (t *userAgentTracker) run(ctx context.Context) {
	ticker := time.NewTicker(t.checkEvery)
	defer ticker.Stop()

	flushAt := nextMidnightUTC(time.Now())

	for {
		select {
		case <-ctx.Done():
			t.reportAndClear()
			return
		case <-t.stop:
			t.reportAndClear()
			return
		case now := <-ticker.C:
			// count distinct agents for the threshold trigger, then check midnight UTC
			var distinct int64
			t.active.Load().Range(func(_, _ any) bool { distinct++; return true })
			if distinct >= t.threshold || !now.Before(flushAt) {
				t.reportAndClear()
				flushAt = nextMidnightUTC(time.Now())
			}
		}
	}
}

// reportAndClear drains the current window and logs each agent's count with
// the bounds of the window it covers.
func (t *userAgentTracker) reportAndClear() {
	counts, total := t.flush()
	if len(counts) == 0 {
		return
	}

	end := time.Now()
	start := time.Unix(0, t.windowStart.Swap(end.UnixNano()))

	data, err := json.Marshal(counts)
	if err != nil {
		t.logger.Error("failed to marshal user agent report", "error", err)
	}
	t.logger.Info("user agent registration report",
		"window_start", start.UTC().Format(time.RFC3339),
		"window_end", end.UTC().Format(time.RFC3339),
		"unique_user_agents", len(counts),
		"total_registrations", total,
		"user_agents", string(data),
	)
}

// nextMidnightUTC returns the upcoming 00:00 UTC boundary strictly after t.
func nextMidnightUTC(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, time.UTC)
}

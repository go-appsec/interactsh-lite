package oobsrv

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserAgentTrackerRecord(t *testing.T) {
	t.Parallel()

	t.Run("tallies_and_flushes", func(t *testing.T) {
		tr := newUserAgentTracker(testLogger(), uaReportThreshold, uaCheckInterval)
		tr.record("curl/8.0")
		tr.record("Mozilla/5.0 (X11; Linux)")
		tr.record("curl/8.0")

		counts, total := tr.flush()
		assert.Equal(t, uint64(2), counts["curl/8.0"])
		assert.Equal(t, uint64(1), counts["Mozilla/5.0 (X11; Linux)"])
		assert.Len(t, counts, 2)
		assert.Equal(t, uint64(3), total)
	})

	t.Run("empty_ua_labeled", func(t *testing.T) {
		tr := newUserAgentTracker(testLogger(), uaReportThreshold, uaCheckInterval)
		tr.record("")
		tr.record("")

		counts, total := tr.flush()
		assert.Equal(t, uint64(2), counts["<empty>"])
		assert.Equal(t, uint64(2), total)
	})

	t.Run("flush_clears_state", func(t *testing.T) {
		tr := newUserAgentTracker(testLogger(), uaReportThreshold, uaCheckInterval)
		tr.record("curl/8.0")
		counts, _ := tr.flush()
		assert.Len(t, counts, 1)

		counts2, total2 := tr.flush()
		assert.Empty(t, counts2)
		assert.Zero(t, total2)
	})
}

func TestUserAgentTrackerReportAndClear(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	tr := newUserAgentTracker(logger, uaReportThreshold, uaCheckInterval)

	tr.record("curl/8.0")
	tr.record("curl/8.0")
	tr.reportAndClear()

	out := buf.String()
	assert.Contains(t, out, "user agent registration report")
	assert.Contains(t, out, `curl/8.0`)
	assert.Contains(t, out, `total_registrations=2`)
	assert.Contains(t, out, "window_start=")
	assert.Contains(t, out, "window_end=")
	assert.Equal(t, 1, strings.Count(out, "registration report"))

	counts, total := tr.flush()
	assert.Empty(t, counts)
	assert.Zero(t, total)
}

func TestUserAgentTrackerDoubleClose(t *testing.T) {
	t.Parallel()

	tr := newUserAgentTracker(testLogger(), uaReportThreshold, uaCheckInterval)
	require.NoError(t, tr.Close())
	require.NoError(t, tr.Close())
}

func TestNextMidnightUTC(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   time.Time
		want time.Time
	}{
		{"mid_day", time.Date(2026, 9, 24, 14, 30, 0, 0, time.UTC), time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)},
		{"just_before_midnight", time.Date(2026, 12, 31, 23, 59, 58, 1e8, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, nextMidnightUTC(tc.in))
		})
	}
}

func TestRegisterRecordsUserAgent(t *testing.T) {
	t.Parallel()

	srv := testServerWithStorage(t)
	key := sharedRSAKey

	body := registerJSON(t, &key.PublicKey, testCorrelationID, "secret-123")
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("User-Agent", "test-agent/1.0")
	srv.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	counts, total := srv.uaTracker.flush()
	assert.Equal(t, uint64(1), counts["test-agent/1.0"])
	assert.Len(t, counts, 1)
	assert.Equal(t, uint64(1), total)
}

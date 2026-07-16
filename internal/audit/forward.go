package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/audit"
	"github.com/kubenexis/knxvault/internal/infra/metrics"
)

const defaultForwardQueueSize = 256

type forwardSink struct {
	url    string
	client *http.Client
	queue  chan *audit.Entry
	// drop/sent for tests when metrics package is not asserted
	dropped atomic.Uint64
	sent    atomic.Uint64
}

var (
	forwardMu  sync.Mutex
	forward    *forwardSink
	forwardURL string
)

func initForwardSink(url string) {
	if url == "" {
		return
	}
	forwardMu.Lock()
	defer forwardMu.Unlock()
	if forward != nil && forwardURL == url {
		return
	}
	// Replace sink when URL changes (tests / reconfigure).
	sink := &forwardSink{
		url: url,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		queue: make(chan *audit.Entry, defaultForwardQueueSize),
	}
	go sink.worker()
	// On URL change, previous worker keeps draining its channel until empty; ops reconfig is rare.
	forward = sink
	forwardURL = url
}

func (f *forwardSink) worker() {
	for entry := range f.queue {
		if entry == nil {
			continue
		}
		body, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(body))
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := f.client.Do(req)
		if err != nil {
			metrics.IncAuditForwardFailed()
			cancel()
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			f.sent.Add(1)
			metrics.IncAuditForwardSent()
		} else {
			metrics.IncAuditForwardFailed()
		}
	}
}

func forwardEntry(entry *audit.Entry) {
	forwardMu.Lock()
	sink := forward
	forwardMu.Unlock()
	if sink == nil || entry == nil {
		return
	}
	// Copy entry and details map so callers can mutate after Record returns.
	cp := *entry
	if entry.Details != nil {
		cp.Details = make(map[string]any, len(entry.Details))
		for k, v := range entry.Details {
			cp.Details[k] = v
		}
	}
	select {
	case sink.queue <- &cp:
	default:
		sink.dropped.Add(1)
		metrics.IncAuditForwardDropped()
	}
}

// ForwardQueueStats returns sent/dropped counters for the current sink (tests).
func ForwardQueueStats() (sent, dropped uint64) {
	forwardMu.Lock()
	defer forwardMu.Unlock()
	if forward == nil {
		return 0, 0
	}
	return forward.sent.Load(), forward.dropped.Load()
}

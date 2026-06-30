package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/audit"
)

type forwardSink struct {
	url    string
	client *http.Client
}

var (
	forwardOnce sync.Once
	forward     *forwardSink
)

func initForwardSink(url string) {
	forwardOnce.Do(func() {
		if url == "" {
			return
		}
		forward = &forwardSink{
			url: url,
			client: &http.Client{
				Timeout: 5 * time.Second,
			},
		}
	})
}

func forwardEntry(entry *audit.Entry) {
	if forward == nil || entry == nil {
		return
	}
	go func() {
		body, err := json.Marshal(entry)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, forward.url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		_, _ = forward.client.Do(req)
	}()
}
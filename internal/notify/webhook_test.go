// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/kubenexis/knxvault/internal/notify"
)

func TestNewWebhookEmptyURL(t *testing.T) {
	if notify.NewWebhook("") != nil {
		t.Fatal("expected nil for empty URL")
	}
}

func TestWebhookSendNilNoop(t *testing.T) {
	var w *notify.Webhook
	if err := w.Send(context.Background(), notify.Event{Event: "x"}); err != nil {
		t.Fatalf("nil receiver: %v", err)
	}
}

func TestWebhookSendPostsJSON(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %s", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		var ev notify.Event
		if err := json.Unmarshal(body, &ev); err != nil {
			t.Errorf("json: %v", err)
		}
		if ev.Event != "rotation" || ev.Path != "kv/app" {
			t.Errorf("payload = %+v", ev)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	wh := notify.NewWebhook(srv.URL)
	if wh == nil {
		t.Fatal("expected webhook")
	}
	if err := wh.Send(context.Background(), notify.Event{Event: "rotation", Path: "kv/app"}); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d", hits.Load())
	}
}

func TestWebhookSendNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	wh := notify.NewWebhook(srv.URL)
	if err := wh.Send(context.Background(), notify.Event{Event: "x"}); err == nil {
		t.Fatal("expected error on 502")
	}
}

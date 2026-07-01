package doctor_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubenexis/knxvault/pkg/client"
	"github.com/kubenexis/knxvault/pkg/doctor"
)

func TestRunnerHealthyDeployment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "healthy",
				"version": "test",
				"sealed":  false,
			})
		case "/ready":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "ready",
				"version": "test",
				"sealed":  false,
			})
		case "/metrics":
			w.WriteHeader(http.StatusOK)
		case "/sys/capabilities":
			if r.Header.Get("Authorization") != "Bearer good-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"capabilities": []string{"sys/policies:read"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	runner := &doctor.Runner{
		Client: client.New(srv.URL, "good-token"),
		Config: doctor.Config{Addr: srv.URL, Token: "good-token"},
	}
	report := runner.Run(context.Background())
	if !report.Healthy {
		t.Fatalf("expected healthy report, got %+v", report)
	}
	if report.Fail != 0 {
		t.Fatalf("fail count = %d, want 0", report.Fail)
	}
	if report.Version != "test" {
		t.Fatalf("version = %q, want test", report.Version)
	}
}

func TestRunnerUnreachableServer(t *testing.T) {
	runner := &doctor.Runner{
		Client: client.New("http://127.0.0.1:1", ""),
		Config: doctor.Config{Addr: "http://127.0.0.1:1"},
	}
	report := runner.Run(context.Background())
	if report.Healthy {
		t.Fatal("expected unhealthy report")
	}
	if report.Fail == 0 {
		t.Fatal("expected at least one failure")
	}
}

func TestRunnerSealedVault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "healthy",
				"version": "test",
				"sealed":  true,
			})
		case "/ready":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":  "ready",
				"version": "test",
				"sealed":  true,
			})
		case "/metrics":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	runner := &doctor.Runner{
		Client: client.New(srv.URL, ""),
		Config: doctor.Config{Addr: srv.URL},
	}
	report := runner.Run(context.Background())
	if report.Healthy {
		t.Fatal("expected unhealthy report for sealed vault")
	}
}

func TestRunnerNotReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "version": "test"})
		case "/ready":
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "not_ready", "version": "test"})
		case "/metrics":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	runner := &doctor.Runner{
		Client: client.New(srv.URL, ""),
		Config: doctor.Config{Addr: srv.URL},
	}
	report := runner.Run(context.Background())
	if report.Healthy {
		t.Fatal("expected unhealthy report for not_ready service")
	}
}

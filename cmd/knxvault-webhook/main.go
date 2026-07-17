// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// knxvault-webhook is a mutating admission webhook that injects CSI volumes for annotated pods.
package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	admissionv1 "k8s.io/api/admission/v1"

	"github.com/kubenexis/knxvault/internal/version"
	"github.com/kubenexis/knxvault/internal/webhook"
)

func main() {
	if version.HandleArgs(os.Args[1:]) {
		return
	}
	version.AnnounceStandard("knxvault-webhook")

	addr := os.Getenv("KNXVAULT_WEBHOOK_ADDR")
	if addr == "" {
		addr = ":9443"
	}
	certFile := os.Getenv("KNXVAULT_WEBHOOK_TLS_CERT_FILE")
	keyFile := os.Getenv("KNXVAULT_WEBHOOK_TLS_KEY_FILE")
	// Allow combined PEM via separate env names used in some charts.
	if certFile == "" {
		certFile = os.Getenv("TLS_CERT_FILE")
	}
	if keyFile == "" {
		keyFile = os.Getenv("TLS_KEY_FILE")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", mutateHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// W50-02: Kubernetes admission webhooks require TLS. Refuse plaintext listen
	// unless explicitly allowed for local unit testing only.
	allowPlain := os.Getenv("KNXVAULT_WEBHOOK_ALLOW_PLAINTEXT") == "true"
	if certFile == "" || keyFile == "" {
		if !allowPlain {
			log.Fatal("KNXVAULT_WEBHOOK_TLS_CERT_FILE and KNXVAULT_WEBHOOK_TLS_KEY_FILE are required (set KNXVAULT_WEBHOOK_ALLOW_PLAINTEXT=true only for local tests)")
		}
		log.Printf("WARNING: knxvault-webhook listening WITHOUT TLS on %s (dev only)", addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Validate key pair early for clear errors.
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		log.Fatalf("load webhook TLS cert: %v", err)
	}
	log.Printf("knxvault-webhook listening with TLS on %s", addr)
	if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatal(err)
	}
}

func mutateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := webhook.HandleAdmissionReview(review)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

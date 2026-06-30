// knxvault-webhook is a mutating admission webhook that injects CSI volumes for annotated pods.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

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
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", mutateHandler)
	log.Printf("knxvault-webhook listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func mutateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
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

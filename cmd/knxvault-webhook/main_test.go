// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestMutateHandlerMethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mutate", nil)
	mutateHandler(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestMutateHandlerBadJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader([]byte("not-json")))
	mutateHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMutateHandlerAdmissionReview(t *testing.T) {
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       "test-uid",
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Resource:  metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			Operation: admissionv1.Create,
			Object: runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"x","namespace":"default"}}`),
			},
		},
	}
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	mutateHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Response == nil {
		t.Fatal("expected AdmissionResponse")
	}
}

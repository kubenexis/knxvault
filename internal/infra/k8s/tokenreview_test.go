// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package k8s_test

import (
	"context"
	"errors"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/kubenexis/knxvault/internal/infra/k8s"
)

func TestParseServiceAccountUsernameViaReview(t *testing.T) {
	cases := []struct {
		username  string
		namespace string
		name      string
	}{
		{"system:serviceaccount:prod:my-app", "prod", "my-app"},
		{"system:serviceaccount:default:builder", "default", "builder"},
	}
	for _, tc := range cases {
		client := fake.NewSimpleClientset()
		client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					User: authenticationv1.UserInfo{
						Username: tc.username,
					},
				},
			}, nil
		})
		reviewer := k8s.NewTokenReviewerFromClient(client)
		result, err := reviewer.Review(context.Background(), "token")
		if err != nil {
			t.Fatalf("Review(%q) = %v", tc.username, err)
		}
		if result.Namespace != tc.namespace || result.ServiceAccountName != tc.name {
			t.Fatalf("Review(%q) identity = %q/%q, want %q/%q",
				tc.username, result.Namespace, result.ServiceAccountName, tc.namespace, tc.name)
		}
	}
}

func TestAPITokenReviewerUnauthenticated(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: false,
			},
		}, nil
	})

	reviewer := k8s.NewTokenReviewerFromClient(client)
	result, err := reviewer.Review(context.Background(), "bad-token")
	if err != nil {
		t.Fatalf("Review() = %v", err)
	}
	if result.Authenticated {
		t.Fatal("expected unauthenticated")
	}
}

func TestAPITokenReviewerAPIError(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("api unavailable")
	})

	reviewer := k8s.NewTokenReviewerFromClient(client)
	if _, err := reviewer.Review(context.Background(), "token"); err == nil {
		t.Fatal("expected API error")
	}
}

func TestAPITokenReviewerNilClient(t *testing.T) {
	reviewer := k8s.NewTokenReviewerFromClient(nil)
	if _, err := reviewer.Review(context.Background(), "token"); err == nil {
		t.Fatal("expected error with nil client")
	}
}

func TestFakeTokenReviewer(t *testing.T) {
	fakeReviewer := &k8s.FakeTokenReviewer{
		Result: &k8s.TokenReviewResult{
			Authenticated:      true,
			Username:           "system:serviceaccount:qa:worker",
			Namespace:          "qa",
			ServiceAccountName: "worker",
		},
	}
	result, err := fakeReviewer.Review(context.Background(), "jwt-123")
	if err != nil {
		t.Fatalf("Review() = %v", err)
	}
	if fakeReviewer.Last != "jwt-123" {
		t.Fatalf("Last = %q", fakeReviewer.Last)
	}
	if result.ServiceAccountName != "worker" {
		t.Fatalf("sa = %q", result.ServiceAccountName)
	}
}

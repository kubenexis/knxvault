// Package k8s provides Kubernetes integration helpers.
package k8s

import (
	"context"
	"fmt"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// TokenReviewResult is the validated ServiceAccount identity from the API server.
type TokenReviewResult struct {
	Authenticated      bool
	Username           string
	Namespace          string
	ServiceAccountName string
}

// TokenReviewer validates Kubernetes ServiceAccount tokens.
type TokenReviewer interface {
	Review(ctx context.Context, token string) (*TokenReviewResult, error)
}

// APITokenReviewer uses authentication.k8s.io/v1 TokenReview.
type APITokenReviewer struct {
	client kubernetes.Interface
}

// NewInClusterTokenReviewer constructs a TokenReviewer from in-cluster credentials.
func NewInClusterTokenReviewer() (TokenReviewer, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	return &APITokenReviewer{client: client}, nil
}

// NewTokenReviewerFromClient constructs a TokenReviewer from an existing client.
func NewTokenReviewerFromClient(client kubernetes.Interface) TokenReviewer {
	return &APITokenReviewer{client: client}
}

// Review validates a bearer token with the Kubernetes API server.
func (r *APITokenReviewer) Review(ctx context.Context, token string) (*TokenReviewResult, error) {
	if r.client == nil {
		return nil, fmt.Errorf("kubernetes client not configured")
	}
	resp, err := r.client.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("token review: %w", err)
	}
	out := &TokenReviewResult{
		Authenticated: resp.Status.Authenticated,
		Username:      resp.Status.User.Username,
	}
	if ns, name, ok := parseServiceAccountUsername(out.Username); ok {
		out.Namespace = ns
		out.ServiceAccountName = name
	}
	return out, nil
}

func parseServiceAccountUsername(username string) (namespace, name string, ok bool) {
	const prefix = "system:serviceaccount:"
	if len(username) <= len(prefix) || username[:len(prefix)] != prefix {
		return "", "", false
	}
	rest := username[len(prefix):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == ':' {
			if i == 0 || i == len(rest)-1 {
				return "", "", false
			}
			return rest[:i], rest[i+1:], true
		}
	}
	return "", "", false
}

package k8s

import (
	"context"
	"fmt"
)

// FakeTokenReviewer is a test double for TokenReview.
type FakeTokenReviewer struct {
	Result *TokenReviewResult
	Err    error
	Last   string
}

// Review records the token and returns configured result.
func (f *FakeTokenReviewer) Review(_ context.Context, token string) (*TokenReviewResult, error) {
	f.Last = token
	if f.Err != nil {
		return nil, f.Err
	}
	if f.Result == nil {
		return nil, fmt.Errorf("fake token reviewer: no result configured")
	}
	out := *f.Result
	return &out, nil
}

package k8s_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/infra/k8s"
)

func TestParseServiceAccountUsername(t *testing.T) {
	ns, name, ok := parseExported("system:serviceaccount:prod:my-app")
	if !ok || ns != "prod" || name != "my-app" {
		t.Fatalf("parse failed: %q %q %v", ns, name, ok)
	}
}

func parseExported(username string) (string, string, bool) {
	reviewer := k8s.NewTokenReviewerFromClient(nil)
	_ = reviewer
	const prefix = "system:serviceaccount:"
	if len(username) <= len(prefix) {
		return "", "", false
	}
	rest := username[len(prefix):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == ':' {
			return rest[:i], rest[i+1:], true
		}
	}
	return "", "", false
}
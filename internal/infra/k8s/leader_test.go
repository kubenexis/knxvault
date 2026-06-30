package k8s_test

import (
	"testing"

	"github.com/kubenexis/knxvault/internal/infra/k8s"
)

func TestInClusterConfigAvailable(t *testing.T) {
	// Outside a cluster this should be false; test only ensures the helper is callable.
	_ = k8s.InClusterConfigAvailable()
}

package statusutil

import (
	"testing"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
)

func TestSetConditionUpsert(t *testing.T) {
	t.Parallel()
	var c []v1alpha1.Condition
	c = ReadyFalse(c, "VaultError", "boom")
	if len(c) != 1 || c[0].Status != "False" {
		t.Fatalf("%+v", c)
	}
	c = ReadyTrue(c, "Issued", "ok")
	if len(c) != 1 || c[0].Status != "True" || c[0].Reason != "Issued" {
		t.Fatalf("%+v", c)
	}
}

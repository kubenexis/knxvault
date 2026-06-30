package inject_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/inject"
)

type stubReader struct {
	data map[string]map[string]any
}

func (s stubReader) ReadSecret(_ context.Context, secretPath string) (map[string]any, error) {
	return s.data[secretPath], nil
}

func TestRendererFilesAndEnv(t *testing.T) {
	reader := stubReader{data: map[string]map[string]any{
		"app/db": {"password": "s3cret"},
	}}
	r := inject.NewRenderer(reader)
	result, err := r.Render(context.Background(), inject.RenderRequest{
		Secrets: []inject.SecretRef{{Path: "app/db", EnvName: "DB_PASSWORD"}},
		Format:  inject.FormatBoth,
	})
	if err != nil {
		t.Fatalf("Render() = %v", err)
	}
	if len(result.Files) != 1 || result.Files[0].Content != "s3cret" {
		t.Fatalf("unexpected files: %+v", result.Files)
	}
	if len(result.Env) != 1 || result.Env[0].Name != "DB_PASSWORD" {
		t.Fatalf("unexpected env: %+v", result.Env)
	}
}

package service_test

import (
	"context"
	"testing"

	"github.com/kubenexis/knxvault/internal/inject"
	"github.com/kubenexis/knxvault/internal/service"
)

type injectStubReader struct {
	data map[string]map[string]any
}

func (s injectStubReader) ReadSecret(_ context.Context, secretPath string) (map[string]any, error) {
	return s.data[secretPath], nil
}

func TestInjectServiceRender(t *testing.T) {
	reader := injectStubReader{data: map[string]map[string]any{
		"app/api": {"token": "abc123"},
	}}
	renderer := inject.NewRenderer(reader)
	svc := service.NewInjectService(renderer, nil)

	result, err := svc.Render(context.Background(), inject.RenderRequest{
		Secrets: []inject.SecretRef{{Path: "app/api", EnvName: "API_TOKEN"}},
		Format:  inject.FormatEnv,
	})
	if err != nil {
		t.Fatalf("Render() = %v", err)
	}
	if len(result.Env) != 1 || result.Env[0].Value != "abc123" {
		t.Fatalf("unexpected env: %+v", result.Env)
	}
}

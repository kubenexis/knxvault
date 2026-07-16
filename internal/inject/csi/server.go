package csi

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/kubenexis/knxvault/internal/infra/metrics"
	"github.com/kubenexis/knxvault/internal/version"
	"google.golang.org/grpc"
	provider "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

const (
	providerName  = "knxvault"
	defaultSocket = "/var/run/secrets-store-csi-providers/knxvault.sock"
)

// Server implements the Secrets Store CSI provider gRPC API.
type Server struct {
	provider.UnimplementedCSIDriverProviderServer
	vault     *VaultClient
	rotations atomic.Uint64
}

// NewServer constructs a CSI provider server.
func NewServer(vault *VaultClient) *Server {
	if vault == nil {
		vault = NewVaultClient()
	}
	return &Server{vault: vault}
}

// Rotations returns the number of detected secret version changes.
func (s *Server) Rotations() uint64 {
	return s.rotations.Load()
}

// Serve listens on a unix socket and serves gRPC until ctx is canceled.
func (s *Server) Serve(ctx context.Context, socketPath string) error {
	if socketPath == "" {
		socketPath = defaultSocket
	}
	// W50-23: restrictive socket directory and socket mode (node-local CSI only).
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create provider socket dir: %w", err)
	}
	_ = os.Chmod(dir, 0o700)
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", socketPath, err)
	}
	if ul, ok := listener.(*net.UnixListener); ok {
		_ = ul
	}
	_ = os.Chmod(socketPath, 0o660)
	grpcServer := grpc.NewServer()
	provider.RegisterCSIDriverProviderServer(grpcServer, s)
	errCh := make(chan error, 1)
	go func() {
		errCh <- grpcServer.Serve(listener)
	}()
	select {
	case <-ctx.Done():
		grpcServer.GracefulStop()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// Version implements CSIDriverProviderServer.
func (s *Server) Version(_ context.Context, _ *provider.VersionRequest) (*provider.VersionResponse, error) {
	return &provider.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    providerName,
		RuntimeVersion: version.Version,
	}, nil
}

// Mount implements CSIDriverProviderServer.
func (s *Server) Mount(ctx context.Context, req *provider.MountRequest) (*provider.MountResponse, error) {
	cfg, err := ParseMountConfig(req.GetAttributes(), req.GetSecrets())
	if err != nil {
		return nil, err
	}
	if cfg.SAToken == "" {
		return nil, fmt.Errorf("service account token missing from mount request")
	}
	clientToken, err := s.vault.LoginKubernetes(ctx, cfg.VaultAddr, cfg.Role, cfg.SAToken)
	if err != nil {
		return nil, fmt.Errorf("kubernetes login: %w", err)
	}

	current := map[string]string{}
	for _, ov := range req.GetCurrentObjectVersion() {
		current[ov.GetId()] = ov.GetVersion()
	}

	var files []*provider.File
	var versions []*provider.ObjectVersion
	for _, obj := range cfg.Objects {
		data, version, err := s.vault.ReadKV(ctx, cfg.VaultAddr, clientToken, obj.Path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", obj.Path, err)
		}
		objectID := objectID(obj)
		versionStr := strconv.Itoa(version)
		if prev, ok := current[objectID]; ok && prev != "" && prev != versionStr {
			s.rotations.Add(1)
			metrics.IncCSIMountRotations()
		}
		versions = append(versions, &provider.ObjectVersion{Id: objectID, Version: versionStr})
		files = append(files, &provider.File{
			Path:     obj.FileName,
			Mode:     int32(0o400),
			Contents: []byte(flattenSecret(data)),
		})
	}

	paths := make([]string, 0, len(cfg.Objects))
	for _, obj := range cfg.Objects {
		paths = append(paths, obj.Path)
	}
	_ = s.vault.RecordCSIMount(ctx, cfg.VaultAddr, clientToken, CSIMountAuditRequest{
		Role:           cfg.Role,
		Namespace:      cfg.Namespace,
		ServiceAccount: cfg.ServiceAccount,
		PodName:        cfg.PodName,
		Paths:          paths,
	})

	return &provider.MountResponse{
		ObjectVersion: versions,
		Files:         files,
	}, nil
}

func objectID(obj ObjectSpec) string {
	return strings.TrimSpace(obj.FileName)
}

func flattenSecret(data map[string]any) string {
	if len(data) == 0 {
		return ""
	}
	if len(data) == 1 {
		for _, v := range data {
			return fmt.Sprint(v)
		}
	}
	var b strings.Builder
	first := true
	for k, v := range data {
		if !first {
			b.WriteByte('\n')
		}
		first = false
		b.WriteString(k)
		b.WriteString("=")
		_, _ = fmt.Fprint(&b, v)
	}
	return b.String()
}

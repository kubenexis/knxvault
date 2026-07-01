package pki

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/kubenexis/knxvault/internal/crypto/openssl"
	"github.com/kubenexis/knxvault/internal/crypto/x509native"
)

const backendOpenSSL = "openssl"

// OpenSSLBackend issues certificates via the sandboxed OpenSSL CLI wrapper.
type OpenSSLBackend struct {
	openssl *openssl.Wrapper
}

// NewOpenSSLBackend constructs an OpenSSL-backed PKI implementation.
func NewOpenSSLBackend(ossl *openssl.Wrapper) *OpenSSLBackend {
	return &OpenSSLBackend{openssl: ossl}
}

// Name returns the backend identifier.
func (b *OpenSSLBackend) Name() string {
	return backendOpenSSL
}

// CreateRoot creates a self-signed root CA using OpenSSL.
func (b *OpenSSLBackend) CreateRoot(ctx context.Context, req RootRequest) (certPEM, keyPEM []byte, err error) {
	ws, err := newWorkspace()
	if err != nil {
		return nil, nil, err
	}
	defer ws.cleanup()

	keyBits := req.KeyBits
	if keyBits == 0 {
		keyBits = 2048
	}
	days := ttlDays(req.TTL)

	if _, err := b.openssl.SafeExec(ctx, []string{
		"genrsa", "-out", ws.path("ca.key"), fmt.Sprintf("%d", keyBits),
	}, nil); err != nil {
		return nil, nil, fmt.Errorf("generate root key: %w", err)
	}

	res, err := b.openssl.SafeExec(ctx, []string{
		"req", "-new", "-x509",
		"-key", ws.path("ca.key"),
		"-out", ws.path("ca.crt"),
		"-days", fmt.Sprintf("%d", days),
		"-subj", subjectDN(req.CommonName),
		"-sha256",
	}, nil)
	if err != nil || res.ExitCode != 0 {
		return nil, nil, fmt.Errorf("create root certificate: %s", strings.TrimSpace(res.Stderr))
	}

	certPEM, err = ws.read("ca.crt")
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = ws.read("ca.key")
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// CreateIntermediate signs an intermediate CA with a parent CA using OpenSSL.
func (b *OpenSSLBackend) CreateIntermediate(ctx context.Context, req IntermediateRequest) (certPEM, keyPEM []byte, err error) {
	ws, err := newWorkspace()
	if err != nil {
		return nil, nil, err
	}
	defer ws.cleanup()

	keyBits := req.KeyBits
	if keyBits == 0 {
		keyBits = 2048
	}
	days := ttlDays(req.TTL)

	if err := ws.write("parent.crt", req.ParentCertPEM); err != nil {
		return nil, nil, err
	}
	if err := ws.write("parent.key", req.ParentKeyPEM); err != nil {
		return nil, nil, err
	}

	if _, err := b.openssl.SafeExec(ctx, []string{
		"genrsa", "-out", ws.path("int.key"), fmt.Sprintf("%d", keyBits),
	}, nil); err != nil {
		return nil, nil, fmt.Errorf("generate intermediate key: %w", err)
	}

	if _, err := b.openssl.SafeExec(ctx, []string{
		"req", "-new",
		"-key", ws.path("int.key"),
		"-out", ws.path("int.csr"),
		"-subj", subjectDN(req.CommonName),
		"-sha256",
	}, nil); err != nil {
		return nil, nil, fmt.Errorf("create intermediate csr: %w", err)
	}

	res, err := b.openssl.SafeExec(ctx, []string{
		"x509", "-req",
		"-in", ws.path("int.csr"),
		"-CA", ws.path("parent.crt"),
		"-CAkey", ws.path("parent.key"),
		"-CAcreateserial",
		"-out", ws.path("int.crt"),
		"-days", fmt.Sprintf("%d", days),
		"-sha256",
	}, nil)
	if err != nil || res.ExitCode != 0 {
		return nil, nil, fmt.Errorf("sign intermediate certificate: %s", strings.TrimSpace(res.Stderr))
	}

	certPEM, err = ws.read("int.crt")
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = ws.read("int.key")
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// IssueCertificate signs a leaf certificate using OpenSSL.
func (b *OpenSSLBackend) IssueCertificate(ctx context.Context, req IssueRequest) (certPEM, keyPEM []byte, err error) {
	ws, err := newWorkspace()
	if err != nil {
		return nil, nil, err
	}
	defer ws.cleanup()

	keyBits := req.KeyBits
	if keyBits == 0 {
		keyBits = 2048
	}
	days := ttlDays(req.TTL)

	if err := ws.write("ca.crt", req.CACertPEM); err != nil {
		return nil, nil, err
	}
	if err := ws.write("ca.key", req.CAKeyPEM); err != nil {
		return nil, nil, err
	}

	if _, err := b.openssl.SafeExec(ctx, []string{
		"genrsa", "-out", ws.path("leaf.key"), fmt.Sprintf("%d", keyBits),
	}, nil); err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}

	if _, err := b.openssl.SafeExec(ctx, []string{
		"req", "-new",
		"-key", ws.path("leaf.key"),
		"-out", ws.path("leaf.csr"),
		"-subj", subjectDN(req.CommonName),
		"-sha256",
	}, nil); err != nil {
		return nil, nil, fmt.Errorf("create leaf csr: %w", err)
	}

	args := []string{
		"x509", "-req",
		"-in", ws.path("leaf.csr"),
		"-CA", ws.path("ca.crt"),
		"-CAkey", ws.path("ca.key"),
		"-CAcreateserial",
		"-out", ws.path("leaf.crt"),
		"-days", fmt.Sprintf("%d", days),
	}
	if len(req.DNSNames) > 0 {
		ext := "[v3_ext]\nsubjectAltName=DNS:" + strings.Join(req.DNSNames, ",DNS:") + "\n"
		if err := ws.write("ext.cnf", []byte(ext)); err != nil {
			return nil, nil, err
		}
		args = append(args, "-extfile", ws.path("ext.cnf"), "-extensions", "v3_ext")
	} else {
		args = append(args, "-sha256")
	}

	res, err := b.openssl.SafeExec(ctx, args, nil)
	if err != nil || res.ExitCode != 0 {
		return nil, nil, fmt.Errorf("sign leaf certificate: %s", strings.TrimSpace(res.Stderr))
	}

	certPEM, err = ws.read("leaf.crt")
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = ws.read("leaf.key")
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// SignCSR signs a PEM CSR with the given CA certificate and key.
func (b *OpenSSLBackend) SignCSR(ctx context.Context, req SignCSRRequest) (certPEM []byte, err error) {
	ws, err := newWorkspace()
	if err != nil {
		return nil, err
	}
	defer ws.cleanup()

	if err := ws.write("ca.crt", req.CACertPEM); err != nil {
		return nil, err
	}
	if err := ws.write("ca.key", req.CAKeyPEM); err != nil {
		return nil, err
	}
	if err := ws.write("req.csr", req.CSRPEM); err != nil {
		return nil, err
	}

	res, err := b.openssl.SafeExec(ctx, []string{
		"x509", "-req",
		"-in", ws.path("req.csr"),
		"-CA", ws.path("ca.crt"),
		"-CAkey", ws.path("ca.key"),
		"-CAcreateserial",
		"-out", ws.path("leaf.crt"),
		"-days", fmt.Sprintf("%d", ttlDays(req.TTL)),
		"-sha256",
	}, nil)
	if err != nil || res.ExitCode != 0 {
		return nil, fmt.Errorf("sign csr: %s", strings.TrimSpace(res.Stderr))
	}
	return ws.read("leaf.crt")
}

// ParseCertificate decodes a PEM certificate via the native fast path.
func (b *OpenSSLBackend) ParseCertificate(pem []byte) (*x509.Certificate, error) {
	return x509native.ParseCertificate(pem)
}

// VerifyChain validates a certificate chain via the native fast path.
func (b *OpenSSLBackend) VerifyChain(leafPEM []byte, intermediatesPEM [][]byte) error {
	return x509native.VerifyChain(leafPEM, intermediatesPEM)
}

func subjectDN(commonName string) string {
	return "/CN=" + commonName + "/O=KNXVault"
}

func ttlDays(ttl time.Duration) int {
	days := int(ttl.Hours() / 24)
	if days < 1 {
		days = 1
	}
	return days
}

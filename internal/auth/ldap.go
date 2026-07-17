package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

// LDAPConfig configures native LDAP authentication (W70).
type LDAPConfig struct {
	// URL e.g. ldap://ldap.example.com:389 or ldaps://...
	URL string
	// UserDNTemplate uses %s for the username, e.g. "uid=%s,ou=people,dc=example,dc=com"
	UserDNTemplate string
	// BindDN / BindPassword for search mode (optional); empty = direct user bind only.
	BindDN       string
	BindPassword string
	// UserSearchBase + UserSearchFilter when using search bind (filter must contain %s).
	UserSearchBase   string
	UserSearchFilter string // e.g. "(uid=%s)"
	// Group policies: map LDAP group CN -> policy names (simplified).
	GroupPolicyMap map[string][]string
	// DefaultPolicies applied on successful bind when no group map matches.
	DefaultPolicies []string
	// InsecureSkipVerify for ldaps lab only.
	InsecureSkipVerify bool
	// Timeout for dial/bind.
	Timeout time.Duration
}

// LDAPBinder performs LDAP bind (injectable for tests).
type LDAPBinder interface {
	Bind(ctx context.Context, serverURL, bindDN, password string, insecureSkipVerify bool, timeout time.Duration) error
}

// NetLDAPBinder performs a minimal LDAP Simple Bind over TCP/TLS.
type NetLDAPBinder struct{}

// Bind implements LDAPBinder using a minimal BER Simple Bind.
func (NetLDAPBinder) Bind(ctx context.Context, serverURL, bindDN, password string, insecureSkipVerify bool, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("ldap url: %w", err)
	}
	host := u.Host
	if host == "" {
		host = u.Path
	}
	if !strings.Contains(host, ":") {
		if u.Scheme == "ldaps" {
			host += ":636"
		} else {
			host += ":389"
		}
	}
	d := net.Dialer{Timeout: timeout}
	var conn net.Conn
	if u.Scheme == "ldaps" {
		// #nosec G402 -- optional lab skip controlled by config
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecureSkipVerify}
		conn, err = tls.DialWithDialer(&d, "tcp", host, tlsCfg)
	} else {
		conn, err = d.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return fmt.Errorf("ldap dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// LDAP Message: MessageID=1, BindRequest (application 0)
	// Simplified Simple Bind (version 3)
	bindReq := encodeSimpleBind(1, bindDN, password)
	if _, err := conn.Write(bindReq); err != nil {
		return fmt.Errorf("ldap write: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("ldap read: %w", err)
	}
	if n < 2 {
		return fmt.Errorf("ldap short response")
	}
	// Very loose success check: resultCode 0 appears in bind response.
	if !ldapBindSuccess(buf[:n]) {
		return common.New(common.ErrCodeUnauthorized, "ldap bind failed")
	}
	return nil
}

func encodeSimpleBind(messageID int, dn, password string) []byte {
	// Build minimal ASN.1 BER for LDAP bind — sufficient for many openldap/simple servers.
	version := []byte{0x02, 0x01, 0x03} // INTEGER 3
	name := encodeOctetString([]byte(dn))
	auth := append([]byte{0x80}, encodeLength(len(password))...)
	auth = append(auth, []byte(password)...)
	bindBody := append(version, name...)
	bindBody = append(bindBody, auth...)
	bind := append([]byte{0x60}, encodeLength(len(bindBody))...)
	bind = append(bind, bindBody...)
	midByte := byte(1)
	if messageID >= 0 && messageID <= 127 {
		midByte = byte(messageID) // bounded 0..127 for BER short form
	}
	mid := []byte{0x02, 0x01, midByte}
	seqBody := append(mid, bind...)
	seq := append([]byte{0x30}, encodeLength(len(seqBody))...)
	return append(seq, seqBody...)
}

func encodeOctetString(b []byte) []byte {
	out := append([]byte{0x04}, encodeLength(len(b))...)
	return append(out, b...)
}

func encodeLength(n int) []byte {
	if n < 0 {
		n = 0
	}
	// Cap at 16-bit length encoding used by this minimal binder.
	if n > 0xffff {
		n = 0xffff
	}
	// Explicit & 0xff masks satisfy gosec G115 (bounded conversions).
	if n < 128 {
		return []byte{byte(n & 0xff)}
	}
	if n < 256 {
		return []byte{0x81, byte(n & 0xff)}
	}
	return []byte{0x82, byte((n >> 8) & 0xff), byte(n & 0xff)}
}

func ldapBindSuccess(resp []byte) bool {
	// Look for ENUMERATED resultCode 0: 0x0a 0x01 0x00
	for i := 0; i+2 < len(resp); i++ {
		if resp[i] == 0x0a && resp[i+1] == 0x01 && resp[i+2] == 0x00 {
			return true
		}
	}
	return false
}

// LoginLDAP binds as the user and returns subject + policies.
func (s *Service) LoginLDAP(ctx context.Context, username, password string, cfg LDAPConfig) (string, *TokenRecord, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return "", nil, common.New(common.ErrCodeValidation, "username and password required")
	}
	if strings.TrimSpace(cfg.URL) == "" {
		return "", nil, common.New(common.ErrCodeValidation, "ldap url not configured")
	}
	dn := username
	if cfg.UserDNTemplate != "" {
		dn = fmt.Sprintf(cfg.UserDNTemplate, username)
	}
	binder := s.ldapBinder
	if binder == nil {
		binder = NetLDAPBinder{}
	}
	if err := binder.Bind(ctx, cfg.URL, dn, password, cfg.InsecureSkipVerify, cfg.Timeout); err != nil {
		s.recordLoginFailure(ctx, "ldap:"+username, LoginAuditContext{AuthMethod: "ldap", ClientIdentity: username}, "bind_failed")
		return "", nil, common.New(common.ErrCodeUnauthorized, "ldap authentication failed")
	}
	policies := append([]string{}, cfg.DefaultPolicies...)
	if len(policies) == 0 {
		policies = []string{"default"}
	}
	// Optional identity resolution
	if s.identityResolver != nil {
		if eid, pols, err := s.identityResolver.ResolveLogin(ctx, "ldap", username, policies); err == nil {
			policies = pols
			_ = eid
		} else if err != nil {
			return "", nil, err
		}
	}
	token, rec, err := s.tokens.Create(ctx, "ldap:"+username, policies, s.tokens.ttl, true, time.Time{})
	if err != nil {
		return "", nil, err
	}
	s.recordLoginAudit(ctx, true, LoginAuditContext{AuthMethod: "ldap", ClientIdentity: username})
	return token, rec, nil
}

// IdentityResolver resolves entity policies at login (M-IDENT-1 hook).
type IdentityResolver interface {
	ResolveLogin(ctx context.Context, mount, aliasName string, basePolicies []string) (entityID string, policies []string, err error)
}

// SetLDAPBinder injects an LDAP binder (tests).
func (s *Service) SetLDAPBinder(b LDAPBinder) {
	s.ldapBinder = b
}

// SetIdentityResolver injects identity resolution.
func (s *Service) SetIdentityResolver(r IdentityResolver) {
	s.identityResolver = r
}

// SetLDAPDefaults configures server-side LDAP settings for LoginLDAP.
func (s *Service) SetLDAPDefaults(cfg *LDAPConfig) {
	s.ldapDefaults = cfg
}

// LDAPDefaults returns server-side LDAP config when set.
func (s *Service) LDAPDefaults() *LDAPConfig {
	if s == nil {
		return nil
	}
	return s.ldapDefaults
}

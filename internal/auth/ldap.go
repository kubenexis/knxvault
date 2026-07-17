// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/kubenexis/knxvault/internal/domain/common"
)

// ldapUsernameRe allows only safe DN component characters (blocks LDAP injection).
var ldapUsernameRe = regexp.MustCompile(`^[a-zA-Z0-9._@+-]{1,128}$`)

// LDAPConfig configures native LDAP authentication (W70 / W74).
// All fields are server-side only — never taken from client headers.
type LDAPConfig struct {
	// URL e.g. ldap://ldap.example.com:389 or ldaps://...
	URL string
	// UserDNTemplate uses %s for the username, e.g. "uid=%s,ou=people,dc=example,dc=com"
	UserDNTemplate string
	// BindDN / BindPassword reserved for future search-bind mode.
	BindDN           string
	BindPassword     string
	UserSearchBase   string
	UserSearchFilter string
	GroupPolicyMap   map[string][]string
	// DefaultPolicies applied on successful bind.
	DefaultPolicies []string
	// InsecureSkipVerify for ldaps lab only (rejected under production profile).
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// LDAPBinder performs LDAP bind (injectable for tests).
type LDAPBinder interface {
	Bind(ctx context.Context, serverURL, bindDN, password string, insecureSkipVerify bool, timeout time.Duration) error
}

// NetLDAPBinder performs a minimal LDAP Simple Bind over TCP/TLS.
type NetLDAPBinder struct{}

// Bind implements LDAPBinder using a minimal BER Simple Bind with structural response parse.
func (NetLDAPBinder) Bind(ctx context.Context, serverURL, bindDN, password string, insecureSkipVerify bool, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("ldap url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "ldap" && scheme != "ldaps" {
		return fmt.Errorf("ldap url scheme must be ldap or ldaps")
	}
	host := u.Host
	if host == "" {
		return fmt.Errorf("ldap url host required")
	}
	if !strings.Contains(host, ":") {
		if scheme == "ldaps" {
			host += ":636"
		} else {
			host += ":389"
		}
	}
	d := net.Dialer{Timeout: timeout}
	var conn net.Conn
	if scheme == "ldaps" {
		// #nosec G402 -- optional lab skip controlled by server config only
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

	const messageID = 1
	bindReq := encodeSimpleBind(messageID, bindDN, password)
	if _, err := conn.Write(bindReq); err != nil {
		return fmt.Errorf("ldap write: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("ldap read: %w", err)
	}
	if err := parseBindResponse(buf[:n], messageID); err != nil {
		return err
	}
	return nil
}

func encodeSimpleBind(messageID int, dn, password string) []byte {
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
		midByte = byte(messageID)
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
	if n > 0xffff {
		n = 0xffff
	}
	if n < 128 {
		return []byte{byte(n & 0xff)}
	}
	if n < 256 {
		return []byte{0x81, byte(n & 0xff)}
	}
	return []byte{0x82, byte((n >> 8) & 0xff), byte(n & 0xff)}
}

// parseBindResponse validates LDAP BindResponse (application tag 1) resultCode == 0.
func parseBindResponse(resp []byte, expectMessageID int) error {
	if len(resp) < 5 {
		return common.New(common.ErrCodeUnauthorized, "ldap bind failed: short response")
	}
	// SEQUENCE
	if resp[0] != 0x30 {
		return common.New(common.ErrCodeUnauthorized, "ldap bind failed: not a sequence")
	}
	off, _, err := readLength(resp, 1)
	if err != nil {
		return common.New(common.ErrCodeUnauthorized, "ldap bind failed: bad length")
	}
	// MessageID INTEGER
	if off >= len(resp) || resp[off] != 0x02 {
		return common.New(common.ErrCodeUnauthorized, "ldap bind failed: missing message id")
	}
	off++
	off, midLen, err := readLength(resp, off)
	if err != nil || midLen < 1 || off+midLen > len(resp) {
		return common.New(common.ErrCodeUnauthorized, "ldap bind failed: bad message id")
	}
	mid := 0
	for i := 0; i < midLen; i++ {
		mid = (mid << 8) | int(resp[off+i])
	}
	off += midLen
	if mid != expectMessageID {
		return common.New(common.ErrCodeUnauthorized, "ldap bind failed: message id mismatch")
	}
	// BindResponse is APPLICATION 1 → tag 0x61
	if off >= len(resp) || resp[off] != 0x61 {
		return common.New(common.ErrCodeUnauthorized, "ldap bind failed: not a bind response")
	}
	off++
	off, bodyLen, err := readLength(resp, off)
	if err != nil || bodyLen < 3 || off+bodyLen > len(resp) {
		return common.New(common.ErrCodeUnauthorized, "ldap bind failed: bad bind body")
	}
	body := resp[off : off+bodyLen]
	// resultCode ENUMERATED at start of BindResponse
	if body[0] != 0x0a {
		return common.New(common.ErrCodeUnauthorized, "ldap bind failed: missing result code")
	}
	bOff, rcLen, err := readLength(body, 1)
	if err != nil || rcLen < 1 || bOff+rcLen > len(body) {
		return common.New(common.ErrCodeUnauthorized, "ldap bind failed: bad result code")
	}
	code := 0
	for i := 0; i < rcLen; i++ {
		code = (code << 8) | int(body[bOff+i])
	}
	if code != 0 {
		return common.New(common.ErrCodeUnauthorized, "ldap bind failed")
	}
	return nil
}

func readLength(b []byte, off int) (newOff int, length int, err error) {
	if off >= len(b) {
		return 0, 0, fmt.Errorf("eof")
	}
	fb := b[off]
	off++
	if fb&0x80 == 0 {
		return off, int(fb), nil
	}
	n := int(fb & 0x7f)
	if n == 0 || n > 2 || off+n > len(b) {
		return 0, 0, fmt.Errorf("bad length")
	}
	length = 0
	for i := 0; i < n; i++ {
		length = (length << 8) | int(b[off])
		off++
	}
	return off, length, nil
}

// ValidateLDAPUsername rejects characters that enable DN/filter injection.
func ValidateLDAPUsername(username string) error {
	username = strings.TrimSpace(username)
	if !ldapUsernameRe.MatchString(username) {
		return common.New(common.ErrCodeValidation, "invalid ldap username")
	}
	return nil
}

// LoginLDAP binds as the user and returns subject + policies.
// Requires server-side LDAPDefaults; client headers are never used (W74-01).
func (s *Service) LoginLDAP(ctx context.Context, username, password string, cfg LDAPConfig) (string, *TokenRecord, error) {
	if s == nil || s.ldapDefaults == nil || strings.TrimSpace(s.ldapDefaults.URL) == "" {
		return "", nil, common.New(common.ErrCodeUnavailable, "ldap authentication is not configured")
	}
	// Always use server defaults; ignore any client-supplied cfg URL/template.
	cfg = *s.ldapDefaults
	if err := ValidateLDAPUsername(username); err != nil {
		return "", nil, err
	}
	if password == "" {
		return "", nil, common.New(common.ErrCodeValidation, "username and password required")
	}
	if strings.TrimSpace(cfg.URL) == "" {
		return "", nil, common.New(common.ErrCodeUnavailable, "ldap authentication is not configured")
	}
	dn := username
	if cfg.UserDNTemplate != "" {
		// Username already allowlisted; safe for single %s substitution.
		if strings.Count(cfg.UserDNTemplate, "%s") != 1 {
			return "", nil, common.New(common.ErrCodeInternal, "ldap user DN template must contain exactly one %s")
		}
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
	if s.identityResolver != nil {
		if _, pols, err := s.identityResolver.ResolveLogin(ctx, "ldap", username, policies); err != nil {
			return "", nil, err
		} else if len(pols) > 0 {
			policies = pols
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

// LDAPConfigured reports whether native LDAP login is enabled.
func (s *Service) LDAPConfigured() bool {
	return s != nil && s.ldapDefaults != nil && strings.TrimSpace(s.ldapDefaults.URL) != ""
}

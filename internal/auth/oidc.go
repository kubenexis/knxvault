// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kubenexis/knxvault/internal/acme"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

type jwksCacheEntry struct {
	keys    map[string]any
	fetched time.Time
}

type jwksCache struct {
	mu      sync.RWMutex
	entries map[string]jwksCacheEntry
	ttl     time.Duration
	max     int
}

func newJWKSCache() *jwksCache {
	return &jwksCache{entries: make(map[string]jwksCacheEntry), ttl: 15 * time.Minute, max: 32}
}

func (c *jwksCache) get(ctx context.Context, jwksURL string) (map[string]any, error) {
	c.mu.RLock()
	if entry, ok := c.entries[jwksURL]; ok && time.Since(entry.fetched) < c.ttl && len(entry.keys) > 0 {
		keys := entry.keys
		c.mu.RUnlock()
		return keys, nil
	}
	c.mu.RUnlock()

	keys, err := fetchJWKS(ctx, jwksURL)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if len(c.entries) >= c.max {
		var oldestURL string
		var oldest time.Time
		for url, e := range c.entries {
			if oldest.IsZero() || e.fetched.Before(oldest) {
				oldest = e.fetched
				oldestURL = url
			}
		}
		delete(c.entries, oldestURL)
	}
	c.entries[jwksURL] = jwksCacheEntry{keys: keys, fetched: time.Now().UTC()}
	c.mu.Unlock()
	return keys, nil
}

func (c *jwksCache) invalidate(jwksURL string) {
	c.mu.Lock()
	delete(c.entries, jwksURL)
	c.mu.Unlock()
}

func fetchJWKS(ctx context.Context, jwksURL string) (map[string]any, error) {
	// W78-08: SSRF gate on JWKS URL (public destinations; loopback allowed for lab/tests).
	if err := validateJWKSURL(jwksURL); err != nil {
		return nil, fmt.Errorf("jwks url: %w", err)
	}
	var client *http.Client
	if acme.IsLoopbackDirectoryURL(jwksURL) {
		client = acme.SafeHTTPClientAllowLoopbackInsecureTLS(10 * time.Second)
	} else {
		client = acme.SafeHTTPClient(10 * time.Second)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	out := make(map[string]any, len(doc.Keys))
	for _, raw := range doc.Keys {
		var meta struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		if meta.Kty != "RSA" || meta.N == "" || meta.E == "" {
			continue
		}
		pub, err := rsaKeyFromJWK(meta.N, meta.E)
		if err != nil {
			continue
		}
		if meta.Kid != "" {
			out[meta.Kid] = pub
		} else {
			out[fmt.Sprintf("key-%d", len(out))] = pub
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable jwks keys")
	}
	return out, nil
}

func rsaKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		nBytes, err = base64.URLEncoding.DecodeString(nB64)
		if err != nil {
			return nil, err
		}
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		eBytes, err = base64.URLEncoding.DecodeString(eB64)
		if err != nil {
			return nil, err
		}
	}
	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	if e == 0 {
		e = 65537
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// OIDCValidator validates OIDC JWTs against role configuration.
type OIDCValidator struct {
	cache *jwksCache
}

// NewOIDCValidator constructs an OIDC validator.
func NewOIDCValidator() *OIDCValidator {
	return &OIDCValidator{cache: newJWKSCache()}
}

// Validate checks a JWT against the role OIDC config.
func (v *OIDCValidator) Validate(ctx context.Context, cfg *domainauth.OIDCConfig, token string) (subject string, claims jwt.MapClaims, err error) {
	if cfg == nil {
		return "", nil, common.New(common.ErrCodeValidation, "oidc not configured for role")
	}
	if cfg.JWKSURL == "" {
		return "", nil, common.New(common.ErrCodeValidation, "oidc jwks_url is required")
	}
	var parsed *jwt.Token
	var parseErr error
	for attempt := 0; attempt < 2; attempt++ {
		keys, keyErr := v.cache.get(ctx, cfg.JWKSURL)
		if keyErr != nil {
			return "", nil, common.Wrap(common.ErrCodeUnauthorized, "jwks unavailable", keyErr)
		}
		parsed, parseErr = jwt.Parse(token, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				if _, ok := t.Method.(*jwt.SigningMethodRSAPSS); !ok {
					return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
				}
			}
			kid, _ := t.Header["kid"].(string)
			if kid != "" {
				if key, ok := keys[kid]; ok {
					return key, nil
				}
				return nil, fmt.Errorf("unknown kid %q", kid)
			}
			if len(keys) == 1 {
				for _, key := range keys {
					return key, nil
				}
			}
			return nil, fmt.Errorf("jwt missing kid with %d jwks keys", len(keys))
		}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}), jwt.WithExpirationRequired())
		if parseErr == nil {
			break
		}
		if attempt == 0 && strings.Contains(parseErr.Error(), "unknown kid") {
			v.cache.invalidate(cfg.JWKSURL)
			continue
		}
		return "", nil, common.Wrap(common.ErrCodeUnauthorized, "invalid oidc jwt", parseErr)
	}
	if parsed == nil {
		return "", nil, common.New(common.ErrCodeUnauthorized, "invalid oidc jwt")
	}
	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return "", nil, common.New(common.ErrCodeUnauthorized, "invalid oidc jwt claims")
	}
	iss, _ := mapClaims["iss"].(string)
	// W78-08 / W79-05: issuer and audience required (fail closed).
	if strings.TrimSpace(cfg.Issuer) == "" {
		return "", nil, common.New(common.ErrCodeUnauthorized, "oidc issuer is required")
	}
	if iss != cfg.Issuer {
		return "", nil, common.New(common.ErrCodeUnauthorized, "issuer mismatch")
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return "", nil, common.New(common.ErrCodeUnauthorized, "oidc audience is required")
	}
	if !audienceMatches(mapClaims["aud"], cfg.Audience) {
		return "", nil, common.New(common.ErrCodeUnauthorized, "audience mismatch")
	}
	sub, _ := mapClaims["sub"].(string)
	if sub == "" {
		return "", nil, common.New(common.ErrCodeUnauthorized, "oidc subject required")
	}
	return sub, mapClaims, nil
}

func audienceMatches(audClaim any, expected string) bool {
	switch v := audClaim.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

// validateJWKSURL allows public https JWKS endpoints and loopback lab servers; blocks
// private/metadata SSRF targets (W78-08). Non-loopback JWKS must use https (W79-05).
func validateJWKSURL(raw string) error {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	if acme.IsLoopbackDirectoryURL(raw) {
		if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
			return fmt.Errorf("jwks url scheme must be http or https")
		}
		return nil
	}
	if !strings.HasPrefix(lower, "https://") {
		return fmt.Errorf("jwks url must use https (except loopback lab)")
	}
	return acme.ValidateOutboundURL(raw)
}

// OIDCTTL returns token TTL capped by role max TTL.
func OIDCTTL(cfg *domainauth.OIDCConfig, defaultTTL time.Duration) time.Duration {
	if cfg != nil && cfg.MaxTTL > 0 {
		max := time.Duration(cfg.MaxTTL) * time.Second
		if defaultTTL > max {
			return max
		}
	}
	if defaultTTL <= 0 {
		return time.Hour
	}
	return defaultTTL
}

// OIDCSubjectLabel formats an audit-friendly subject.
func OIDCSubjectLabel(issuer, sub string) string {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return "oidc:" + sub
	}
	return fmt.Sprintf("oidc:%s:%s", issuer, sub)
}

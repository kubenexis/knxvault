package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestOIDCValidatorRejectsWrongAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	}))
	defer jwks.Close()

	validator := auth.NewOIDCValidator()
	cfg := &domainauth.OIDCConfig{
		Issuer:   "https://issuer.example",
		Audience: "expected-aud",
		JWKSURL:  jwks.URL,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://issuer.example",
		"aud": "wrong-aud",
		"sub": "actor-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	_, _, err = validator.Validate(context.Background(), cfg, signed)
	if err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestOIDCValidatorAcceptsValidToken(t *testing.T) {
	key, jwks, cfg := testOIDCSetup(t)
	defer jwks.Close()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://issuer.example",
		"aud": "expected-aud",
		"sub": "user-42",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	sub, claims, err := auth.NewOIDCValidator().Validate(context.Background(), cfg, signed)
	if err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if sub != "user-42" {
		t.Fatalf("subject = %q", sub)
	}
	if claims["aud"] != "expected-aud" {
		t.Fatalf("claims = %#v", claims)
	}
}

func TestOIDCValidatorRejectsWrongIssuer(t *testing.T) {
	key, jwks, cfg := testOIDCSetup(t)
	defer jwks.Close()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://other.example",
		"aud": "expected-aud",
		"sub": "user-42",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	_, _, err = auth.NewOIDCValidator().Validate(context.Background(), cfg, signed)
	if err == nil {
		t.Fatal("expected issuer mismatch error")
	}
}

func TestOIDCValidatorRejectsExpiredToken(t *testing.T) {
	key, jwks, cfg := testOIDCSetup(t)
	defer jwks.Close()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://issuer.example",
		"aud": "expected-aud",
		"sub": "user-42",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	_, _, err = auth.NewOIDCValidator().Validate(context.Background(), cfg, signed)
	if err == nil {
		t.Fatal("expected expired token error")
	}
}

func TestOIDCValidatorRejectsMissingSubject(t *testing.T) {
	key, jwks, cfg := testOIDCSetup(t)
	defer jwks.Close()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://issuer.example",
		"aud": "expected-aud",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	_, _, err = auth.NewOIDCValidator().Validate(context.Background(), cfg, signed)
	if err == nil {
		t.Fatal("expected missing subject error")
	}
}

func testOIDCSetup(t *testing.T) (*rsa.PrivateKey, *httptest.Server, *domainauth.OIDCConfig) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "test",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}},
		})
	}))
	cfg := &domainauth.OIDCConfig{
		Issuer:   "https://issuer.example",
		Audience: "expected-aud",
		JWKSURL:  jwks.URL,
	}
	return key, jwks, cfg
}

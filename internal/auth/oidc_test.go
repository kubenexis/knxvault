package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kubenexis/knxvault/internal/auth"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
)

func TestOIDCValidatorMultiIdPJWKS(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key1: %v", err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key2: %v", err)
	}

	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDoc(key1, "kid-1"))
	}))
	defer srv1.Close()
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksDoc(key2, "kid-2"))
	}))
	defer srv2.Close()

	validator := auth.NewOIDCValidator()
	cfg1 := &domainauth.OIDCConfig{JWKSURL: srv1.URL, Issuer: "https://idp1.example", Audience: "knxvault"}
	cfg2 := &domainauth.OIDCConfig{JWKSURL: srv2.URL, Issuer: "https://idp2.example", Audience: "knxvault"}

	token1 := signOIDCTestJWT(t, key1, "kid-1", "https://idp1.example", "knxvault", "user-1")
	token2 := signOIDCTestJWT(t, key2, "kid-2", "https://idp2.example", "knxvault", "user-2")

	ctx := context.Background()
	if _, _, err := validator.Validate(ctx, cfg1, token1); err != nil {
		t.Fatalf("validate idp1 token with idp1: %v", err)
	}
	if _, _, err := validator.Validate(ctx, cfg2, token2); err != nil {
		t.Fatalf("validate idp2 token with idp2: %v", err)
	}
	if _, _, err := validator.Validate(ctx, cfg2, token1); err == nil {
		t.Fatal("expected idp1 token to fail against idp2 jwks")
	}
}

func jwksDoc(key *rsa.PrivateKey, kid string) map[string]any {
	return map[string]any{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   "AQAB",
			},
		},
	}
}

func signOIDCTestJWT(t *testing.T, key *rsa.PrivateKey, kid, iss, aud, sub string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": iss,
		"aud": aud,
		"sub": sub,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signed
}

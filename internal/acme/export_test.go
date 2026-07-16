package acme

import (
	"crypto"
	"net/http"
)

// SetNewACMEForTest injects a mock ACME factory (tests only).
func SetNewACMEForTest(c *Client, fn func(key crypto.Signer, directory string, hc *http.Client) ACMEAPI) {
	c.newACME = fn
}

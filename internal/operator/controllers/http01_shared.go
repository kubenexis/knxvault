package controllers

import "github.com/kubenexis/knxvault/internal/acme"

// SharedHTTP01 is the process-wide HTTP-01 presenter used when the operator
// listens on KNXVAULT_ACME_HTTP01_ADDR (W50-07).
var SharedHTTP01 *acme.MemoryHTTP01

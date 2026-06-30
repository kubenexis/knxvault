// Package migrations embeds SQL schema migrations (LLD §4.D.1).
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS

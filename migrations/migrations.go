// Package migrations embeds TomPanel's canonical SQL migration files.
package migrations

import "embed"

// FS contains the SQL migrations applied by the runtime.
//
//go:embed *.sql
var FS embed.FS

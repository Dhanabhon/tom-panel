// Package web embeds TomPanel's server-rendered browser assets.
package web

import "embed"

// FS contains the production templates and static assets.
//
//go:embed templates/*.html static/*
var FS embed.FS

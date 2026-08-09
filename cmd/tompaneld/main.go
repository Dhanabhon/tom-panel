package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/Dhanabhon/tom-panel/internal/config"
	"github.com/Dhanabhon/tom-panel/internal/web"
)

func main() {
	configPath := flag.String("config", "/etc/tompanel/config.toml", "path to configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	app, err := web.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("tompaneld listening on %s", cfg.Listen)
	log.Fatal(http.ListenAndServe(cfg.Listen, app.Handler()))
}

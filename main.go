package main

import (
	"embed"
	"flag"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

// version is the application version string.
// It is set at build time via:
//
//	-ldflags "-X main.version=v1.2.0-abc1234"
//
// If not set, it defaults to "v0.1.0".
var version = "v0.1.0"

func main() {
	// Parse command-line flags
	dbPath := flag.String("db-path", "", "Path to the database file (default: platform-specific user data directory)")
	flag.Parse()

	// Create an instance of the app structure
	app := NewApp(*dbPath, version)


	// Configure and start application
	err := wails.Run(&options.App{
		Title:  "twSecScan",
		Width:  1024,
		Height: 768,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 59, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		log.Fatal(err)
	}
}

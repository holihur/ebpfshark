package server

import (
	"embed"
	"io/fs"
	"runtime"
)

//go:embed all:webdist
var webAssets embed.FS

// WebFS returns the embedded web UI, rooted at the dist directory.
func WebFS() (fs.FS, error) {
	return fs.Sub(webAssets, "webdist")
}

func runtimeVersion() string { return runtime.Version() }

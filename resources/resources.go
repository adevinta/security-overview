package resources

import (
	"embed"
)

//go:embed analytics-dev.js croco.png full-report.html style.css analytics-pro.js favicon.png overview.html script.js
var Files embed.FS

package resources

import (
	"embed"
)

//go:embed analytics-dev.js overview.html full-report.html favicon.png croco.png analytics-pro.js analytics-dev.js
var Files embed.FS

package vulcan

import (
	"sync"

	"github.com/adevinta/security-overview/vulcan/persistence"
	"github.com/adevinta/vulcan-groupie/pkg/groupie"
	"github.com/adevinta/vulcan-groupie/pkg/models"
	vulcanreport "github.com/adevinta/vulcan-report"
)

// ReportData contains all required data for a detailed report
type ReportData struct {
	ScanID  string `json:"scan_id"`
	Date    string
	Reports []vulcanreport.Report

	Risk                     vulcanreport.SeverityRank  `json:"risk"`
	ActionRequired           bool                       `json:"action_required"`
	Assets                   []string                   `json:"assets"`
	CheckTypes               []string                   `json:"checktypes"`
	VulnerabilitiesPerImpact []VulnerabilitiesPerImpact `json:"vulnerabilities_per_impact"`
	VulnerabilitiesPerAsset  []VulnerabilitiesPerAsset  `json:"vulnerabilities_per_asset"`
	TopVulnerabilities       []VulnerabilityCount       `json:"top_vulnerabilities"`
	NumberOfVulnerableAssets int                        `json:"number_vulnerable_assets"`
	Vulnerabilities          []Vulnerability            `json:"vulnerabilities"`
	Groups                   []models.Group             `json:"groups"`
	GroupsPerAsset           map[string][]models.Group  `json:"groups_per_asset"`

	reportWG    sync.WaitGroup
	workerWG    sync.WaitGroup
	countChecks int
	mu          sync.RWMutex
	chanChecks  chan persistence.Check
	groupie     *groupie.Groupie
}

// VulnerabilitiesPerImpact associates an impact with a number of vulnerabilities
type VulnerabilitiesPerImpact struct {
	Impact          string  `json:"impact"`
	Vulnerabilities float64 `json:"vulnerabilities"`
}

// VulnerabilitiesPerAsset associates a checktype with a number of vulnerabilities
type VulnerabilitiesPerAsset struct {
	Asset           string `json:"asset_name"`
	Vulnerabilities int    `json:"vulnerabilities"`
}

// VulnerabilityCount ...
type VulnerabilityCount struct {
	Summary string `json:"summary"`
	Impact  string `json:"impact"`
	Count   int    `json:"count"`
}

// Vulnerability represents a vulnerability found on an asset by a checktype
type Vulnerability struct {
	Asset           string                     `json:"asset"`
	AffectedTargets []string                   `json:"affected_targets"`
	CheckType       string                     `json:"checktype"`
	Options         string                     `json:"options"`
	Vulnerability   vulcanreport.Vulnerability `json:"vulnerability"`
}

package report

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/danfaizer/go-chart"

	"github.com/adevinta/security-overview/config"
	"github.com/adevinta/security-overview/vulcan"
)

// GenerateOverview generates content of the overview report suitable to be send as email.
// Returns the url or the file path, depending on configuration, where the report generated is stored.
func GenerateOverview(conf config.Config, awsConfig *aws.Config, resourcesPath, folder string, reportData *vulcan.ReportData, teamName, teamID, scanID string) (string, error) {
	// assemble the array of vulnerabilities per checktype
	vulnerabilityPerImpact := []chart.Value{}
	vulnerabilitiesCount := 0
	for _, impact := range reportData.VulnerabilitiesPerImpact {
		vulnerabilityPerImpact = append(vulnerabilityPerImpact, chart.Value{Value: float64(impact.Vulnerabilities), Label: impact.Impact})

		//Ignore INFO
		if impact.Impact != "Info" {
			vulnerabilitiesCount = vulnerabilitiesCount + int(impact.Vulnerabilities)
		}
	}

	// assemble the array of vulnerabilities per asset
	vulnerabilityPerAsset := []chart.Value{}
	for _, vuln := range reportData.VulnerabilitiesPerAsset {
		vulnerabilityPerAsset = append(vulnerabilityPerAsset, chart.Value{Value: float64(vuln.Vulnerabilities), Label: vuln.Asset})
	}

	var risk, riskStyle string
	var actionRequired, actionRequiredStyle string
	// determine styles and messages about risk
	switch {
	case reportData.Risk == 0:
		risk = "NONE"
		riskStyle = "green"
		actionRequired = "NO ACTION REQUIRED"
		actionRequiredStyle = "green"
	case reportData.Risk <= 1:
		risk = "LOW"
		riskStyle = "yellow"
		actionRequired = "ACTION SUGGESTED"
		actionRequiredStyle = "green"
	case reportData.Risk <= 2:
		risk = "MEDIUM"
		riskStyle = "orange"
		actionRequired = "ACTION SUGGESTED"
		actionRequiredStyle = "green"
	case reportData.Risk <= 3:
		risk = "HIGH"
		riskStyle = "red"
		actionRequired = "ACTION REQUIRED"
		actionRequiredStyle = "red"
	case reportData.Risk <= 4:
		risk = "CRITICAL"
		riskStyle = "purple"
		actionRequired = "ACTION REQUIRED"
		actionRequiredStyle = "red"
	default:
		risk = "UNKNOWN"
		riskStyle = "grey"
		actionRequired = "NO ACTION REQUIRED"
		actionRequiredStyle = "green"
	}

	// obtain the scan date
	endDate, err := time.Parse("2006-01-02", reportData.Date)
	if err != nil {
		return "", err
	}
	// obtain the scan date - 1 month
	startDate := endDate.AddDate(0, -1, 0)

	// Generate the ful report link poiting to the vulcan-api report view endpoint
	// e.g. https://vulcan.example.com/api/v1/report?team_id=%s&scan_id=%s
	fullReportLink := fmt.Sprintf(conf.Endpoints.ViewReport, url.QueryEscape(teamID), url.QueryEscape(scanID))
	fullReportURL, err := url.Parse(fullReportLink)
	if err != nil {
		return "", err
	}
	// Wrap the link over the redirect endpoint that ensures the user is connected to heimdall.
	// Example of RedirectURL https://vulcan-insights-redirect.example.com/index.html?reportUrl=vulcan-dev.example.com/api/v1/report?team_id=team-id&scan_id=scan-id
	RedirectURLURL, err := url.Parse(conf.Endpoints.RedirectURL)
	if err != nil {
		return "", err
	}
	// The query param on the RedirectURLURL that contains the path to redirect after
	// checking the user is on Heimdall needs to be specified without the schema.
	RedirectURLURL.RawQuery = RedirectURLURL.RawQuery + url.QueryEscape(fullReportURL.String())

	overview := Overview{
		ResourcesPath:  resourcesPath,
		LocalTempDir:   conf.General.LocalTempDir,
		CompanyName:    conf.General.CompanyName,
		SupportEmail:   conf.General.SupportEmail,
		ContactEmail:   conf.General.ContactEmail,
		ContactChannel: conf.General.ContactChannel,
		Bucket:         conf.S3.PublicBucket,
		Folder:         folder,
		Filename:       reportData.ScanID + "-overview",
		Extension:      ".html",
		LinkFullReport: RedirectURLURL.String(),
		// LinkFullReport:   conf.Proxy.Endpoint + "/" + folder + "/" + reportData.ScanID + "-full-report.html",
		// PathToFullReport: strings.Replace(conf.Proxy.Endpoint, "https://", "", -1) + "/" + folder + "/" + reportData.ScanID + "-full-report.html",
		Proxy:                conf.Proxy.Endpoint,
		UploadToS3:           conf.S3.Upload,
		AWSConfig:            awsConfig,
		ScanID:               reportData.ScanID,
		TeamID:               teamID,
		TeamName:             teamName,
		ActionRequired:       actionRequired,
		ActionRequiredStyle:  actionRequiredStyle,
		ImpactLevel:          risk,
		ImpactLevelStyle:     riskStyle,
		VulnerabilitiesCount: strconv.Itoa(vulnerabilitiesCount),
		TopVulnerabilities:   reportData.TopVulnerabilities,
		VulnerabilityPerImpact: Chart{
			Values: vulnerabilityPerImpact,
		},
		VulnerabilityPerAsset: Chart{
			Values: vulnerabilityPerAsset,
		},
		//Since this is the first report, we are going to show just a flat line
		//over the last 30 days
		VulnerableAssetsChart: HistoricalChart{
			Dates:  []time.Time{startDate, endDate},
			Values: []float64{float64(reportData.NumberOfVulnerableAssets), float64(reportData.NumberOfVulnerableAssets)},
		},

		//Since this is the first report, we are going to show just a flat line
		//over the last 30 days
		ImpactLevelChart: HistoricalChart{
			Dates:  []time.Time{startDate, endDate},
			Values: []float64{float64(reportData.Risk), float64(reportData.Risk)},
		},
	}

	return overview.Generate()
}

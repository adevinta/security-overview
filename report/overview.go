package report

import (
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/danfaizer/go-chart"

	"github.com/adevinta/security-overview/resources"
	"github.com/adevinta/security-overview/vulcan"
)

const (
	templateFile = "overview.html"
)

// Overview ...
type Overview struct {
	LocalTempDir string

	Bucket         string
	Folder         string
	Filename       string
	Extension      string
	LinkFullReport string
	CompanyName    string
	SupportEmail   string
	ContactEmail   string
	ContactChannel string
	Proxy          string
	UploadToS3     bool
	AWSConfig      *aws.Config

	ScanID   string
	TeamID   string
	TeamName string

	ActionRequired       string
	ActionRequiredStyle  string
	ImpactLevel          string
	ImpactLevelStyle     string
	VulnerabilitiesCount string

	TopVulnerabilities     []vulcan.VulnerabilityCount
	VulnerabilityPerImpact Chart
	VulnerabilityPerAsset  Chart
	VulnerableAssetsChart  HistoricalChart
	ImpactLevelChart       HistoricalChart
}

type Chart struct {
	ImageURL string
	Values   []chart.Value
}

type HistoricalChart struct {
	ImageURL string
	Values   []float64
	Dates    []time.Time
}

func (o *Overview) Generate() (string, error) {
	err := o.HandleVulnerabilityPerImpact()
	if err != nil {
		return "", err
	}

	err = o.HandleVulnerabilityPerAsset()
	if err != nil {
		return "", err
	}

	//err = o.HandleVulnerableAssetsChart()
	//if err != nil {
	//	return "", err
	//}

	//err = o.HandleImpactLevelChart()
	//if err != nil {
	//	return "", err
	//}

	reportTemplate := template.New("report").Funcs(template.FuncMap{"now": time.Now})

	reportHTML, err := reportTemplate.ParseFS(resources.Files, templateFile)
	if err != nil {
		return "", err
	}

	overviewHTMLURL, overviewHTMLPath, err := GenerateLocalFilePathAndRemoteURL("", o.Bucket, o.Folder, filepath.Join(o.LocalTempDir, o.ScanID), o.Filename, o.Extension)
	if err != nil {
		return "", err
	}

	file, err := os.Create(overviewHTMLPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	err = reportHTML.ExecuteTemplate(file, templateFile, o)
	if err != nil {
		return "", err
	}

	return overviewHTMLURL, nil
}

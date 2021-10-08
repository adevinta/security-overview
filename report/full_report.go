package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/microcosm-cc/bluemonday"
	blackfriday "github.com/russross/blackfriday/v2"

	"github.com/adevinta/security-overview/resources"
	"github.com/adevinta/security-overview/utils"
	"github.com/adevinta/security-overview/vulcan"
	vulcanreport "github.com/adevinta/vulcan-report"
)

const (
	templateFileFullReport = "full-report.html"
)

type VulnsCount struct {
	Info     int `json:"info" xml:"info"`
	Low      int `json:"low" xml:"low"`
	Medium   int `json:"medium" xml:"medium"`
	High     int `json:"high" xml:"high"`
	Critical int `json:"critical" xml:"critical"`
	Issues   int `json:"total" xml:"total"`
}

type AssetVulns struct {
	Asset string                 `json:"asset" xml:"asset"`
	Count VulnsCount             `json:"vulnerabilities_count" xml:"vulnerabilities_count"`
	Vulns []vulcan.Vulnerability `json:"vulnerabilities" xml:"vulnerabilities"`
}

type Group struct {
	Summary         string                 `json:"summary" xml:"summary"`
	Recommendations []string               `json:"recommendations" xml:"recommendations"`
	Vulns           []vulcan.Vulnerability `json:"vulnerabilities" xml:"vulnerabilities"`
}

type FullReport struct {
	Jira                string      `json:"-" xml:"-"`
	ContactChannel      string      `json:"-" xml:"-"`
	ContactEmail        string      `json:"-" xml:"-"`
	LocalTempDir        string      `json:"-" xml:"-"`
	PublicResourcesPath string      `json:"-" xml:"-"`
	Bucket              string      `json:"-" xml:"-"`
	Folder              string      `json:"-" xml:"-"`
	Filename            string      `json:"-" xml:"-"`
	Extension           string      `json:"-" xml:"-"`
	Proxy               string      `json:"-" xml:"-"`
	UploadToS3          bool        `json:"-" xml:"-"`
	AWSConfig           *aws.Config `json:"-" xml:"-"`

	Risk                    vulcanreport.SeverityRank `json:"risk" xml:"risk"`
	ScanID                  string                    `json:"scan_id" xml:"scan_id"`
	ScanTime                string                    `json:"scan_time" xml:"scan_time"`
	TeamName                string                    `json:"team_name" xml:"team_name"`
	Vulnerabilities         int                       `json:"vulnerabilities" xml:"vulnerabilities"`
	VulnerabilitiesPerAsset []AssetVulns              `json:"assets" xml:"assets"`
	Groups                  []Group                   `json:"groups" xml:"groups"`

	GAID string `json:"-" xml:"-"`

	HomeURL           string `json:"-" xml:"-"`
	JSONExportURL     string `json:"-" xml:"-"`
	ManageAssetsURL   string `json:"-" xml:"-"`
	DetailsURL        string `json:"-" xml:"-"`
	DashboardURL      string `json:"-" xml:"-"`
	DocumentationLink string `json:"-" xml:"-"`
	RoadmapLink       string `json:"-" xml:""`
}

var templateFuncMap = template.FuncMap{
	"upload": func(path string) string {
		panic(fmt.Errorf("upload template func not implemented"))
		return ""
	},
	"severityToStr": func(severity vulcanreport.SeverityRank) string {
		switch severity {
		case vulcanreport.SeverityNone:
			return "Info"
		case vulcanreport.SeverityLow:
			return "Low"
		case vulcanreport.SeverityMedium:
			return "Medium"
		case vulcanreport.SeverityHigh:
			return "High"
		case vulcanreport.SeverityCritical:
			return "Critical"
		default:
			return "N/A"
		}
	},
	"severityToClass": func(severity vulcanreport.SeverityRank) string {
		switch severity {
		case vulcanreport.SeverityNone:
			return "info"
		case vulcanreport.SeverityLow:
			return "low"
		case vulcanreport.SeverityMedium:
			return "medium"
		case vulcanreport.SeverityHigh:
			return "high"
		case vulcanreport.SeverityCritical:
			return "critical"
		default:
			return ""
		}
	},
	"formatHTML": func(text string) template.HTML {
		unsafe := blackfriday.Run([]byte(text))
		sanitized := bluemonday.UGCPolicy().SanitizeBytes(unsafe)
		return template.HTML(string(sanitized))
	},
	"formatResources": func(text string) template.HTML {
		text = strings.TrimLeft(text, " \t")
		unsafe := blackfriday.Run([]byte(text))
		p := bluemonday.NewPolicy()
		p.AllowStandardURLs()
		p.AllowAttrs("href").OnElements("a")
		sanitized := p.SanitizeBytes(unsafe)
		return template.HTML(string(sanitized))
	},
	"urlDomain": func(urlString string) string {
		u, err := url.Parse(urlString)
		if err != nil {
			return ""
		}

		return u.Host
	},
	"roundScore": func(score float32) string {
		return fmt.Sprintf("%.1f", score)
	},
	"isEmpty": func(text string) bool {
		t1 := strings.Trim(text, "\n")
		t1 = strings.Trim(t1, " ")
		return len(t1) == 0
	},
	"printRecommendations": func(r []string) bool {
		for _, recommendation := range r {
			if recommendation != "n/a" {
				return true
			}
		}
		return false
	},
	"countGroupVulnerabilities": func(g Group) int {
		count := 0
		for _, vuln := range g.Vulns {
			if vuln.Vulnerability.Score > 0.0 {
				count++
			}
		}
		return count
	},
}

func (fr *FullReport) Generate() (string, error) {
	generateFuncs := templateFuncMap
	generateFuncs["upload"] = func(path string) string {
		ext := filepath.Ext(path)
		body, errUploadFile := resources.Files.ReadFile(path)
		if errUploadFile != nil {
			log.Println(errUploadFile)
			return ""
		}
		url, errUploadFile := utils.GenerateLocalFile(body, fr.Proxy, fr.Bucket, fr.Folder, filepath.Join(fr.LocalTempDir, fr.ScanID, fr.Bucket, fr.Folder), "", ext)
		if errUploadFile != nil {
			log.Println(errUploadFile)
		}

		return url
	}

	reportTemplate := template.New("full-report").Funcs(generateFuncs)
	fullReportJSON, err := json.MarshalIndent(fr, "", "  ")
	if err != nil {
		return "", err
	}

	reportJSONURL, err := utils.GenerateLocalFile(fullReportJSON, fr.Proxy, fr.Bucket, fr.Folder, filepath.Join(fr.LocalTempDir, fr.ScanID, fr.Bucket, fr.Folder), fr.Filename, ".json")
	if err != nil {
		return "", err
	}

	fr.JSONExportURL = reportJSONURL

	log.Println("full report JSON: ", fr.JSONExportURL)

	reportHTML, err := reportTemplate.ParseFS(resources.Files, templateFileFullReport)
	if err != nil {
		return "", err
	}

	var output []byte
	buf := bytes.NewBuffer(output)
	err = reportHTML.ExecuteTemplate(buf, templateFileFullReport, fr)
	if err != nil {
		return "", err
	}
	fmt.Printf("filename %s\n", fr.Filename)
	return utils.GenerateLocalFile(buf.Bytes(), fr.Proxy, fr.Bucket, fr.Folder, filepath.Join(fr.LocalTempDir, fr.ScanID, fr.Bucket, fr.Folder), fr.Filename, fr.Extension)
}

func (fr *FullReport) Regenerate() (string, error) {
	// This is a hack to allow the public resources font-awesome, bulma, et al.
	// to be served locally. In other words the assets referred with .Proxy in the
	// template.
	fr.Proxy = "."

	regenerateFuncs := templateFuncMap
	regenerateFuncs["upload"] = func(relativePath string) string {
		content, err := resources.Files.ReadFile(relativePath)
		if err != nil {
			panic(err)
		}
		filename := filepath.Base(relativePath)
		destPath := filepath.Join(fr.Folder, filename)
		err = ioutil.WriteFile(destPath, content, os.ModePerm)
		if err != nil {
			panic(err)
		}
		return relativePath
	}

	reportTemplate := template.New("full-report").Funcs(regenerateFuncs)
	reportHTML, err := reportTemplate.ParseFS(resources.Files, templateFileFullReport)
	if err != nil {
		return "", err
	}

	var output []byte
	buf := bytes.NewBuffer(output)
	err = reportHTML.ExecuteTemplate(buf, templateFileFullReport, fr)
	if err != nil {
		return "", err
	}
	content := buf.Bytes()
	reportPath := filepath.Join(fr.Folder, fmt.Sprintf("%s%s", fr.Filename, fr.Extension))
	err = ioutil.WriteFile(reportPath, content, os.ModePerm)
	if err != nil {
		return "", err
	}
	// Copy the directory with the public assets.
	err = utils.CopyDir(fr.PublicResourcesPath, filepath.Join(fr.Folder, "public"))
	if err != nil {
		fmt.Print(err)
		return "", err
	}
	return reportPath, nil
}

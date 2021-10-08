package report

import (
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/adevinta/security-overview/config"
	"github.com/adevinta/security-overview/vulcan"
	report "github.com/adevinta/vulcan-report"
)

const ManageAssetsPath = "assets/edit-assets.html"
const DetailsPath = "assets/index.html"
const DashboardPath = "dashboard.html"

func maxScore(vulns []vulcan.Vulnerability) float32 {
	if len(vulns) == 0 {
		return 0
	}

	return vulns[0].Vulnerability.Score
}

// GenerateFullReport generates the html report suitable to be published as a static web page.
// Returns the url or the file path, depending on configuration, where the report generated is stored.
func GenerateFullReport(conf config.Config, awsConfig *aws.Config, folder string, reportData *vulcan.ReportData, teamName string) (string, error) {
	mapVulnerabilitiesPerAsset := make(map[string][]vulcan.Vulnerability)
	aggregatedVulnerabilities := []report.Vulnerability{}

	for _, vuln := range reportData.Vulnerabilities {
		mapVulnerabilitiesPerAsset[vuln.Asset] = append(mapVulnerabilitiesPerAsset[vuln.Asset], vuln)
		aggregatedVulnerabilities = append(aggregatedVulnerabilities, vuln.Vulnerability)
	}
	aggregatedScore := report.AggregateScore(aggregatedVulnerabilities)

	vulnCount := 0
	assetVulnsSlice := []AssetVulns{}
	for asset, vulns := range mapVulnerabilitiesPerAsset {
		var count VulnsCount
		for _, v := range vulns {
			switch v.Vulnerability.Severity() {
			case 0:
				count.Info++
			case 1:
				count.Low++
				count.Issues++
			case 2:
				count.Medium++
				count.Issues++
			case 3:
				count.High++
				count.Issues++
			case 4:
				count.Critical++
				count.Issues++
			}
		}
		assetVulnsSlice = append(assetVulnsSlice, AssetVulns{Asset: asset, Count: count, Vulns: vulns})
		vulnCount += count.Low + count.Medium + count.High
	}

	sort.SliceStable(assetVulnsSlice, func(i, j int) bool {
		if maxScore(assetVulnsSlice[i].Vulns) == maxScore(assetVulnsSlice[j].Vulns) {
			return assetVulnsSlice[i].Asset < assetVulnsSlice[j].Asset
		}
		return maxScore(assetVulnsSlice[i].Vulns) > maxScore(assetVulnsSlice[j].Vulns)
	})

	scanTimeFmt, err := time.Parse("2006-01-02", reportData.Date)
	if err != nil {
		return "", err
	}

	assetVulnsSlice = convertToGroups(reportData, assetVulnsSlice)

	sort.SliceStable(assetVulnsSlice, func(i, j int) bool {
		if maxScore(assetVulnsSlice[i].Vulns) == maxScore(assetVulnsSlice[j].Vulns) {
			return assetVulnsSlice[i].Asset < assetVulnsSlice[j].Asset
		}
		return maxScore(assetVulnsSlice[i].Vulns) > maxScore(assetVulnsSlice[j].Vulns)
	})
	fullReport := FullReport{
		LocalTempDir:    conf.General.LocalTempDir,
		HomeURL:         conf.Endpoints.VulcanUI,
		ManageAssetsURL: conf.Endpoints.VulcanUI + ManageAssetsPath,
		DetailsURL:      conf.Endpoints.VulcanUI + DetailsPath,
		DashboardURL:    conf.Endpoints.VulcanUI + DashboardPath,
		Bucket:          conf.S3.PrivateBucket,
		Folder:          folder,
		Filename:        reportData.ScanID + "-full-report",
		Extension:       ".html",
		Proxy:           conf.Proxy.Endpoint,
		UploadToS3:      conf.S3.Upload,
		AWSConfig:       awsConfig,

		Risk:                    report.RankSeverity(aggregatedScore),
		ScanID:                  reportData.ScanID,
		ScanTime:                scanTimeFmt.Format("02/01/2006"),
		TeamName:                teamName,
		Vulnerabilities:         vulnCount,
		VulnerabilitiesPerAsset: assetVulnsSlice,
		Groups:                  generateGroups(reportData),
		DocumentationLink:       conf.General.DocumentationLink,
		RoadmapLink:             conf.General.RoadmapLink,
		Jira:                    conf.General.Jira,
		ContactEmail:            conf.General.ContactEmail,
		ContactChannel:          conf.General.ContactChannel,

		GAID: conf.Analytics.GAID,
	}

	return fullReport.Generate()
}

func convertToGroups(reportData *vulcan.ReportData, assetVulnsSlice []AssetVulns) []AssetVulns {
	var result []AssetVulns
	for _, entry := range assetVulnsSlice {
		av := AssetVulns{
			Asset: entry.Asset,
			Count: entry.Count,
		}

		groups := reportData.GroupsPerAsset[entry.Asset]
		for _, group := range groups {
			if len(group.Vulnerabilities) < 1 {
				continue
			}

			var vulns []report.Vulnerability
			// groupedRecommendations contain all the recommendations for a
			// vulnerability with multiple "sub-vunerabilities".
			// This only applies to vulcan-tls check, which for example:
			// Weak SSL/TLS Ciphersuites vulnerability is formed by multiple
			// vulnerabilities (one per ciphersuite) with same impact level.
			var groupedRecommendations string
			for _, vuln := range group.Vulnerabilities {
				if vuln.ImpactDetails == "" {
					for _, vulnvulns := range vuln.Vulnerabilities {
						for _, recommendation := range vulnvulns.Recommendations {
							groupedRecommendations = fmt.Sprintf("%s%s\n", groupedRecommendations, recommendation)
						}
						vuln.Vulnerability.Details = groupedRecommendations
					}
				}
				vulns = append(vulns, vuln.Vulnerability)
			}

			v := vulcan.Vulnerability{
				Asset: entry.Asset,
				Vulnerability: report.Vulnerability{
					Summary:         group.Summary,
					Recommendations: group.Recommendations,
					Score:           group.Vulnerabilities[0].Score,
				},
			}
			v.Vulnerability.Vulnerabilities = vulns

			av.Vulns = append(av.Vulns, v)
		}

		result = append(result, av)
	}

	return result
}

func generateGroups(reportData *vulcan.ReportData) []Group {
	var result []Group
	for _, group := range reportData.Groups {
		if len(group.Vulnerabilities) < 1 {
			continue
		}

		var vulns []vulcan.Vulnerability
		for _, vuln := range group.Vulnerabilities {
			v := vulcan.Vulnerability{
				AffectedTargets: vuln.AffectedTargets,
				CheckType:       vuln.Checktype,
				Vulnerability:   vuln.Vulnerability,
			}
			vulns = append(vulns, v)
		}

		g := Group{
			Summary:         group.Summary,
			Recommendations: group.Recommendations,
			Vulns:           vulns,
		}

		result = append(result, g)
	}

	return result
}

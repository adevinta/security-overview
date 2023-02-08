package vulcan

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sort"
	"time"

	"github.com/adevinta/security-overview/config"
	"github.com/adevinta/security-overview/vulcan/persistence"
	"github.com/adevinta/security-overview/vulcan/results"
	"github.com/adevinta/vulcan-groupie/db"
	"github.com/adevinta/vulcan-groupie/pkg/groupie"
	"github.com/adevinta/vulcan-groupie/pkg/models"
	vulcanreport "github.com/adevinta/vulcan-report"
)

func (rp *ReportData) worker(done <-chan struct{}, conf config.Config) {
	defer rp.workerWG.Done()
	var exit bool

	for !exit {
		select {
		case check := <-rp.chanChecks:
			report, err := results.GetReport(conf.Results.Endpoint, check.Report)
			if err != nil {
				log.Printf("ERROR getting results for check-id: %s. Error detail:%v.\n The security overview will not include results of these checks.", check, err)
				rp.reportWG.Done()
				continue
			}

			rp.mu.Lock()
			rp.countChecks++
			if rp.countChecks%100 == 0 {
				log.Printf("%d", rp.countChecks)
			}
			//time.Sleep(200 * time.Millisecond)

			rp.Reports = append(rp.Reports, *report)
			rp.mu.Unlock()

			rp.reportWG.Done()
		case <-done:
			exit = true
		}
	}
}

// GetReportData extracts information about the given scan from
// both vulcan-persistence API and vulcan-results API
func GetReportData(conf config.Config, scanID string) (*ReportData, error) {
	m := db.NewMemDB()
	g := groupie.New(m)

	rp := &ReportData{ScanID: scanID, countChecks: 0, chanChecks: make(chan persistence.Check, conf.Results.Workers), groupie: g}
	//We need to retrieve the scan date because the reports on vulcan Results
	//are partitioned by date
	date, err := persistence.GetDate(conf.Persistence.Endpoint, rp.ScanID)
	if err != nil {
		return nil, err
	}
	rp.Date = date

	log.Printf("Getting checks from persistence api...")
	checks, err := persistence.GetChecks(conf.Persistence.Endpoint, rp.ScanID)
	if err != nil {
		return nil, err
	}

	log.Printf("Getting reports from results api...")
	rp.Reports = []vulcanreport.Report{}
	ctx, done := context.WithCancel(context.Background())
	for i := 0; i < conf.Results.Workers; i++ {
		rp.workerWG.Add(1)
		go rp.worker(ctx.Done(), conf)
	}

	log.Printf("Sending %d checks to channel...", len(checks))
	for _, check := range checks {
		rp.reportWG.Add(1)
		rp.chanChecks <- check
	}

	// This waits for all the reports to be done.
	rp.reportWG.Wait()

	// Signal workers to finish.
	done()
	// This waits for all workers to be finished.
	rp.workerWG.Wait()

	rp.setRisk()
	rp.setActionRequired()
	rp.setAssets()
	rp.setChecktypes()
	rp.setVulnerabilitiesPerImpact()
	rp.setVulnerabilitiesPerAssets()
	rp.setTopVulnerabilities()
	rp.setNumberOfVulnerableAssets()
	rp.setAllVulnerabilities()

	// Update grouping database with scan before retrieving groups.
	if err := g.UpdateFromScan(scanID, date, rp.Reports); err != nil {
		return nil, err
	}

	if err := rp.setGroups(); err != nil {
		return nil, err
	}

	if err := rp.setGroupsPerAsset(); err != nil {
		return nil, err
	}

	return rp, nil
}

// GetReportDataFromFile extracts information about a check report
// stored in file.
func GetReportDataFromFile(conf config.Config, scanID, path string) (*ReportData, error) {
	m := db.NewMemDB()
	g := groupie.New(m)

	rp := &ReportData{ScanID: scanID, countChecks: 0, groupie: g}
	date := time.Now().Format("2006-01-02")
	rp.Date = date
	log.Printf("Getting reports from results json file...")
	rp.Reports = []vulcanreport.Report{}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r vulcanreport.Report
	err = json.Unmarshal(content, &r)
	if err != nil {
		return nil, err
	}
	rp.Reports = append(rp.Reports, r)
	rp.setRisk()
	rp.setActionRequired()
	rp.setAssets()
	rp.setChecktypes()
	rp.setVulnerabilitiesPerImpact()
	rp.setVulnerabilitiesPerAssets()
	rp.setTopVulnerabilities()
	rp.setNumberOfVulnerableAssets()
	rp.setAllVulnerabilities()

	// Update grouping database with scan before retrieving groups.
	if err := g.UpdateFromScan(scanID, date, rp.Reports); err != nil {
		return nil, err
	}

	if err := rp.setGroups(); err != nil {
		return nil, err
	}

	if err := rp.setGroupsPerAsset(); err != nil {
		return nil, err
	}

	return rp, nil
}

// Risk is defined as the maximum severity found among all vulnerabilities
func (rp *ReportData) setRisk() {
	severityLevel := vulcanreport.SeverityNone
loop:
	for _, report := range rp.Reports {
		for _, vuln := range report.Vulnerabilities {
			severity := vuln.Severity()
			if severity > severityLevel {
				severityLevel = severity
			}

			//currently the max severity level is 4: critical
			if severityLevel == vulcanreport.SeverityCritical {
				break loop
			}
		}
	}

	rp.Risk = severityLevel
}

// An action is required if the risk is high or critical
func (rp *ReportData) setActionRequired() {
	rp.ActionRequired = rp.Risk >= vulcanreport.SeverityHigh
}

// Find all scanned assets in this report
func (rp *ReportData) setAssets() {
	assets := []string{}
	assetMap := make(map[string]bool)

	for _, report := range rp.Reports {
		assetMap[report.Target] = true
	}

	for asset := range assetMap {
		assets = append(assets, asset)
	}

	sort.Strings(sort.StringSlice(assets))

	rp.Assets = assets
}

// Find all checktypes in this report
func (rp *ReportData) setChecktypes() {
	checktypes := []string{}
	checktypeMap := make(map[string]bool)

	for _, report := range rp.Reports {
		checktypeMap[report.ChecktypeName] = true
	}

	for checktype := range checktypeMap {
		checktypes = append(checktypes, checktype)
	}
	sort.Strings(sort.StringSlice(checktypes))

	rp.CheckTypes = checktypes
}

// populates an array containing the number of vulnerabilities per checktype
func (rp *ReportData) setVulnerabilitiesPerImpact() {
	// in the cases where a report does not contains any vulnerabilities,
	// the pie chart library will complain about not being able to Generate
	// a chart with only zero values. By putting a 0.01 we can work around
	// this situation.
	vulnerabilitiesMap := map[string]float64{
		"Info":     0.01,
		"Low":      0.01,
		"Medium":   0.01,
		"High":     0.01,
		"Critical": 0.01,
	}
	result := []VulnerabilitiesPerImpact{}

	for _, report := range rp.Reports {
		for _, vulnerability := range report.Vulnerabilities {
			severity := vulnerability.Severity()
			vulnerabilitiesMap[severityToString(severity)] = vulnerabilitiesMap[severityToString(severity)] + 1
		}
	}

	result = append(result, VulnerabilitiesPerImpact{Impact: "Critical", Vulnerabilities: vulnerabilitiesMap["Critical"]})
	result = append(result, VulnerabilitiesPerImpact{Impact: "High", Vulnerabilities: vulnerabilitiesMap["High"]})
	result = append(result, VulnerabilitiesPerImpact{Impact: "Medium", Vulnerabilities: vulnerabilitiesMap["Medium"]})
	result = append(result, VulnerabilitiesPerImpact{Impact: "Low", Vulnerabilities: vulnerabilitiesMap["Low"]})
	result = append(result, VulnerabilitiesPerImpact{Impact: "Info", Vulnerabilities: vulnerabilitiesMap["Info"]})

	rp.VulnerabilitiesPerImpact = result
}

// populates an array containing the assets ordered by number of vulnerabilities
func (rp *ReportData) setVulnerabilitiesPerAssets() {
	var assetVulnerabilitiesMap = make(map[string]int)

	var result = []VulnerabilitiesPerAsset{}

	// first we get the Vulnerability number per assets
	for _, report := range rp.Reports {
		numVulnerabilities := 0
		for _, v := range report.Vulnerabilities {
			//Ignore INFO
			severity := v.Severity()
			if severity != vulcanreport.SeverityNone {
				numVulnerabilities++
			}
		}

		assetVulnerabilitiesMap[report.Target] = assetVulnerabilitiesMap[report.Target] + numVulnerabilities
	}

	// hen we created a slice of AssetVulnerability
	for target, numVulnerabilities := range assetVulnerabilitiesMap {
		assetVulnerability := VulnerabilitiesPerAsset{Asset: target, Vulnerabilities: numVulnerabilities}
		result = append(result, assetVulnerability)
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Vulnerabilities == result[j].Vulnerabilities {
			return result[i].Asset > result[j].Asset
		}
		return result[i].Vulnerabilities > result[j].Vulnerabilities
	})

	rp.VulnerabilitiesPerAsset = result
}

// find the number of vulnerables assets
func (rp *ReportData) setNumberOfVulnerableAssets() {
	var vulnerableAssets = make(map[string]bool)

	// first we get the Vulnerability number per assets
	for _, report := range rp.Reports {
		numVulnerabilities := len(report.Vulnerabilities)
		if numVulnerabilities > 0 {
			vulnerableAssets[report.Target] = true
		}
	}

	rp.NumberOfVulnerableAssets = len(vulnerableAssets)
}

// find all vulnerabilties on a report
func (rp *ReportData) setTopVulnerabilities() {
	vulnerabilitiesCountMap := make(map[string]map[string]VulnerabilityCount)
	result := []VulnerabilityCount{}

	// first we get the Vulnerability number per assets
	for _, report := range rp.Reports {
		for _, vuln := range report.Vulnerabilities {
			title := vuln.Summary
			impact := severityToString(vuln.Severity())
			// check if specific vulnerability exists
			if _, ok := vulnerabilitiesCountMap[title]; !ok {
				vulnerabilitiesCountMap[title] = make(map[string]VulnerabilityCount)
				vulnerabilitiesCountMap[title][impact] = VulnerabilityCount{
					Summary: vuln.Summary,
					Impact:  severityToString(vuln.Severity()),
					Count:   1,
				}
				continue
			}
			// if specific vulnerability exists: count and group by impact
			if _, ok := vulnerabilitiesCountMap[title][impact]; !ok {
				vulnerabilitiesCountMap[title][impact] = VulnerabilityCount{
					Summary: vuln.Summary,
					Impact:  severityToString(vuln.Severity()),
					Count:   1,
				}
				continue
			}
			vulnerabilitiesCountPerImpact := vulnerabilitiesCountMap[title][impact]
			vulnerabilitiesCountPerImpact.Count++
			vulnerabilitiesCountMap[title][impact] = vulnerabilitiesCountPerImpact
		}
	}

	// then we created a slice of AssetVulnerabilit with Severity over Low and None
	for _, vuln := range vulnerabilitiesCountMap {
		for _, vulnPerImpact := range vuln {
			if vulnPerImpact.Impact != severityToString(vulcanreport.SeverityNone) && vulnPerImpact.Impact != severityToString(vulcanreport.SeverityLow) {
				result = append(result, vulnPerImpact)
			}
		}
	}

	sort.SliceStable(result, func(i, j int) bool {
		if severityStringToInt(result[i].Impact) == severityStringToInt(result[j].Impact) {
			if result[i].Count == result[j].Count {
				return result[i].Summary < result[j].Summary
			}

			return result[i].Count > result[j].Count
		}

		return severityStringToInt(result[i].Impact) > severityStringToInt(result[j].Impact)
	})

	if len(result) > 10 {
		rp.TopVulnerabilities = result[0:9]
	} else {
		rp.TopVulnerabilities = result
	}
}

// find all vulnerabilties on a report
func (rp *ReportData) setAllVulnerabilities() {
	result := []Vulnerability{}

	for _, report := range rp.Reports {
		for _, vulnerability := range report.Vulnerabilities {
			vulnerabilityDescription := Vulnerability{
				Asset:         report.Target,
				CheckType:     report.ChecktypeName,
				Vulnerability: vulnerability,
				Options:       report.Options,
			}
			result = append(result, vulnerabilityDescription)
		}
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Vulnerability.Severity() == result[j].Vulnerability.Severity() {
			if result[i].Asset == result[j].Asset {
				if result[i].CheckType == result[j].CheckType {
					return result[i].CheckType < result[j].CheckType
				}
			}
			return result[i].Asset < result[j].Asset
		}
		return result[i].Vulnerability.Severity() > result[j].Vulnerability.Severity()
	})

	rp.Vulnerabilities = result
}

func (rp *ReportData) setGroups() error {
	g, err := rp.groupie.GroupByScan(rp.ScanID)
	if err != nil {
		return err
	}
	rp.Groups = g
	return nil
}

func (rp *ReportData) setGroupsPerAsset() error {
	m := make(map[string][]models.Group)
	for _, target := range rp.Assets {
		groups, err := rp.groupie.GroupByTarget(target)
		if err != nil {
			return err
		}
		m[target] = groups
	}
	rp.GroupsPerAsset = m

	return nil
}

func severityToString(severity vulcanreport.SeverityRank) string {
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
}

func severityStringToInt(severityString string) int {
	switch severityString {
	case "Info":
		return 0
	case "Low":
		return 1
	case "Medium":
		return 2
	case "High":
		return 3
	case "Critical":
		return 4
	default:
		return 0
	}
}

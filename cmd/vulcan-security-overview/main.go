package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	insights "github.com/adevinta/security-overview"
	"github.com/adevinta/security-overview/report"
	uuid "github.com/satori/go.uuid"
)

var (
	scanID     = flag.String("scan-id", "", "[required] vulcan scan ID. Ex: -scan-id=\"123456-aaaa-bbbb-cccc-123456\"")
	teamName   = flag.String("team-name", "", "[required] Team name. This will be used as the key for future Reports. Ex: -team-name=\"Purple Team\"")
	teamID     = flag.String("team-id", "", "[required] Team id. The vulcan-api teamid that the scan belongs to")
	configFile = flag.String("config", "", "[required] config file")
	regen      = flag.String("regen", "", `regenerate a report from json report previously generated.
Takes a path to the json file. for instance ./report.json`)
	resources  = flag.String("resources", "", "[required with regen] path to the folder containing non public resources")
	presources = flag.String("presources", "", "[required with regen] path to the folder containing public resources")
	assetsURL  = flag.String("assetsurl", "", "[required with regen] specifies the base url where the manage")
	detailsURL = flag.String("detailsurl", "", "[required with regen] specifies the base url of the details")
	output     = flag.String("output", "", "[required with regen] specifies the directory to save regenerated report")
	check      = flag.String("check", "", `generates the security overview for test pourposes from a single check report stored in 
a file. The only other required flag is -config. Example: vulcan-security-overview -config ".security-overview.toml" -check check_report.json`)
)

func checkParams() bool {

	if (*scanID == "" || *teamName == "" || *configFile == "" || *teamID == "") && *regen == "" {
		flag.Usage()
		return false
	}
	return true
}

func checkRegenerateParams() bool {
	return *presources != "" && *resources != "" && *output != "" && *assetsURL != ""
}

func main() {
	flag.Parse()
	if *check != "" {
		if *configFile == "" {
			flag.Usage()
		}
		err := generateFromFile(*check, *configFile)
		if err != nil {
			panic(err)
		}
		return
	}
	if !checkParams() {
		return
	}

	if *regen != "" {
		if ok := checkRegenerateParams(); !ok {
			flag.Usage()
			return
		}
		err := regenerateReport()
		if err != nil {
			panic(err)
		}
		return
	}

	dr, err := insights.NewDetailedReport(*configFile, *teamName, *scanID, *teamID)
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}

	err = dr.GenerateLocalFiles()
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}

	err = dr.UploadFilesToS3()
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}
}

func generateFromFile(path string, config string) error {
	teamName := "Team 1"
	uuid, err := uuid.NewV1()
	if err != nil {
		return err
	}
	id := uuid.String()
	dr, err := insights.NewDetailedReport(config, teamName, id, id)
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}

	err = dr.GenerateLocalFilesFromCheck(path)
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}

	err = dr.UploadFilesToS3()
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}
	return nil
}

func regenerateReport() error {
	jsonFilePath, err := filepath.Abs(*regen)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return err
	}
	r := report.FullReport{}
	err = json.Unmarshal(data, &r)
	if err != nil {
		return err
	}

	outputDir := *output
	if r.ScanID == "" {
		r.ScanID = "scan"
	}
	err = os.MkdirAll(filepath.Join(outputDir), os.ModePerm)
	if err != nil {
		return err
	}
	r.PublicResourcesPath = *presources
	r.ManageAssetsURL = *assetsURL
	r.DetailsURL = *detailsURL
	r.Folder = outputDir
	r.Filename = "report"
	r.Extension = ".html"
	content, err := r.Regenerate()
	if err != nil {
		return err
	}
	fmt.Printf("report generated at %s\n", string(content))
	return nil
}

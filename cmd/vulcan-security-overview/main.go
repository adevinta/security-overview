package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	insights "github.com/adevinta/security-overview"
	"github.com/adevinta/security-overview/report"
)

var (
	scanID     = flag.String("scan-id", "", "[required] vulcan scan ID. Ex: -scan-id=\"123456-aaaa-bbbb-cccc-123456\"")
	teamName   = flag.String("team-name", "", "[required] Team name. This will be used as the key for future Reports. Ex: -team-name=\"Purple Team\"")
	teamID     = flag.String("team-id", "", "[required] Team id. The vulcan-api teamid that the scan belongs to")
	configFile = flag.String("config", "", "[required] config file")
	dummy      = flag.Bool("dummy", false, "use dummy data (see dummy.go)")
	regen      = flag.String("regen", "", `regenerate a report from json report previously generated.
Takes a path to the json file. for instance ./report.json`)
	resources  = flag.String("resources", "", "[required with regen] path to the folder containing non public resources")
	presources = flag.String("presources", "", "[required with regen] path to the folder containing public resources")
	assetsURL  = flag.String("assetsurl", "", "[required with regen] specifies the base url where the manage")
	detailsURL = flag.String("detailsurl", "", "[required with regen] specifies the base url of the details")
	output     = flag.String("output", "", "[required with regen] specifies the directory to save regenerated report")
)

func checkParams() bool {
	flag.Parse()
	if (*scanID == "" || *teamName == "" || *configFile == "" || *teamID == "") && !*dummy && *regen == "" {
		flag.Usage()
		return false
	}
	return true
}

func checkRegenerateParams() bool {
	return *presources != "" && *resources != "" && *output != "" && *assetsURL != ""
}

func main() {
	if !checkParams() {
		return
	}

	if *dummy {
		generateDummy()
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

func regenerateReport() error {
	resourcesPath := *resources
	jsonFilePath, err := filepath.Abs(*regen)
	if err != nil {
		return err
	}
	data, err := ioutil.ReadFile(jsonFilePath)
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
	r.ResourcesPath = resourcesPath
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

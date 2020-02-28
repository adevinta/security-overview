package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"mime"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	//"github.com/agext/levenshtein"
	"github.com/AllenDang/simhash"

	"github.com/adevinta/security-overview/config"
	"github.com/adevinta/security-overview/report"
	"github.com/adevinta/security-overview/vulcan"
)

func generateDummy() {
	reportData := vulcan.ReportData{}

	dummyData, err := ioutil.ReadFile("Metasploitable.json")
	if err != nil {
		panic(err)
	}
	json.Unmarshal(dummyData, &reportData)

	vulnStore := []*vulcan.Vulnerability{}
	for i := 0; i < len(reportData.Vulnerabilities); i++ {
		vulnStore = append(vulnStore, &reportData.Vulnerabilities[i])
	}

	log.Printf("[%v]", vulnStore)
	for i := 0; i < len(vulnStore); i++ {
		if vulnStore[i] == nil {
			continue
		}
		vGroup := &vulcan.Vulnerability{}
		vGroup.Vulnerability.Vulnerabilities = append(vGroup.Vulnerability.Vulnerabilities, vulnStore[i].Vulnerability)
		log.Printf("[%v]: %v", i, vulnStore[i].Vulnerability.Summary)
		words1 := strings.Split(strings.ToLower(vulnStore[i].Vulnerability.Summary), " ")

		for j := i + 1; j < len(vulnStore); j++ {
			if i != j && vulnStore[j] != nil {

				words2 := strings.Split(strings.ToLower(vulnStore[j].Vulnerability.Summary), " ")
				if words1[0] == words2[0] {
					d1 := simhash.GetLikenessValue(
						vulnStore[i].Vulnerability.Summary,
						vulnStore[j].Vulnerability.Summary)
					if len(vulnStore[i].Vulnerability.Recommendations) == 0 ||
						len(vulnStore[j].Vulnerability.Recommendations) == 0 {
						continue
					}
					d2 := simhash.GetLikenessValue(
						vulnStore[i].Vulnerability.Recommendations[0],
						vulnStore[j].Vulnerability.Recommendations[0])
					if (d1 > 0.8 || d1+d2 >= 1.4) && len(vulnStore[i].Vulnerability.Recommendations[0]) > 6 && len(vulnStore[j].Vulnerability.Recommendations[0]) > 6 {
						log.Printf("[%v]: %v", vulnStore[j].Vulnerability.Summary, d1)
						vGroup.Vulnerability.Vulnerabilities = append(vGroup.Vulnerability.Vulnerabilities, vulnStore[j].Vulnerability)
						vulnStore[j] = nil
					}
				}
			}
		}

		if len(vGroup.Vulnerability.Vulnerabilities) > 1 {
			maxReco := ""
			for _, vuln := range vGroup.Vulnerability.Vulnerabilities {
				for _, recom := range vuln.Recommendations {
					if recom > maxReco {
						maxReco = recom
					}
				}
			}

			vulnStore[i].Vulnerability.Summary = "[GROUP] " + vulnStore[i].Vulnerability.Summary + " And Similar"
			vulnStore[i].Vulnerability.Description = maxReco
			vulnStore[i].Vulnerability.Vulnerabilities = vGroup.Vulnerability.Vulnerabilities
		}

	}

	reportData.Vulnerabilities = []vulcan.Vulnerability{}
	for i := 0; i < len(vulnStore); i++ {
		if vulnStore[i] == nil {
			continue
		}
		reportData.Vulnerabilities = append(reportData.Vulnerabilities, *vulnStore[i])
	}

	conf, err := config.ReadConfig(*configFile)
	if err != nil {
		panic(err)
	}
	awsConfig := aws.NewConfig().WithRegion("eu-west-1").WithMaxRetries(3)

	sha := fmt.Sprintf("%x", sha256.Sum256([]byte(*teamName)))
	folder := filepath.Join(sha, reportData.Date)

	email, err := report.GenerateOverview(conf, awsConfig, conf.General.ResourcesPath, folder, &reportData, *teamName, *teamID, *scanID)
	if err != nil {
		panic(err)
	}

	URL, err := report.GenerateFullReport(conf, awsConfig, conf.General.ResourcesPath, folder, &reportData, *teamName)
	if err != nil {
		panic(err)
	}

	log.Printf("email:\t%v", email)
	log.Printf("url:\t%v", URL)

	bucket := conf.S3.PrivateBucket
	localPath := filepath.Join(conf.General.LocalTempDir, *scanID, bucket, folder)
	fd, err := os.Open(localPath)
	if err != nil {
		panic(err)
	}
	defer fd.Close()
	files, _ := fd.Readdir(-1)
	for _, file := range files {
		log.Printf("upload: %v/%v", bucket, filepath.Join(folder, file.Name()))
		err = uploadFile(bucket, filepath.Join(folder, file.Name()), localPath, file.Name())
		if err != nil {
			panic(err)
		}
	}
}

func uploadFile(bucket, key, localPath, filename string) error {
	awsConfig := aws.NewConfig().WithRegion("eu-west-1").WithMaxRetries(3)

	svc := s3.New(session.New(awsConfig))
	localFilename := filepath.Join(localPath, filename)
	contentType := mime.TypeByExtension(filepath.Ext(localFilename))
	body, err := ioutil.ReadFile(localFilename)
	if err != nil {
		return err
	}

	params := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String(contentType),
	}

	_, err = svc.PutObject(params)
	if err != nil {
		return err
	}

	return nil
}

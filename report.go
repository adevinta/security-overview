package insights

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/adevinta/security-overview/config"
	"github.com/adevinta/security-overview/report"
	"github.com/adevinta/security-overview/vulcan"
)

// DetailedReport represents a detailed report, with an HTML email and a full
// report
type DetailedReport struct {
	teamName  string
	scanID    string
	teamID    string
	folder    string
	URL       string
	Email     string
	Risk      int
	conf      config.Config
	awsConfig *aws.Config
}

// NewDetailedReport  initializes and returns a new DetailedReport
func NewDetailedReport(configFile, teamName, scanID, teamID string) (*DetailedReport, error) {
	conf, err := config.ReadConfig(configFile)
	if err != nil {
		return nil, err
	}

	detailedReport := &DetailedReport{
		teamName: teamName,
		scanID:   scanID,
		teamID:   teamID,
		conf:     conf,
	}

	// Set default region for AWS config.
	if conf.S3.Region == "" {
		conf.S3.Region = "eu-west-1"
	}
	detailedReport.awsConfig = aws.NewConfig().WithRegion(conf.S3.Region).WithMaxRetries(3)
	if conf.S3.Endpoint != "" {
		detailedReport.awsConfig.WithEndpoint(conf.S3.Endpoint).WithS3ForcePathStyle(conf.S3.PathStyle)
	}

	return detailedReport, nil
}

// GenerateLocalFiles grabs data for a fiven scan ID from Vulcan Core and saves
// the HTML enauk and the  full report in a local folder
func (d *DetailedReport) GenerateLocalFiles() error {
	// Grabs scan data on Vulcan Core
	reportData, err := vulcan.GetReportData(d.conf, d.scanID)
	if err != nil {
		return err
	}

	file, err := os.Create(d.teamName + ".json")
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(reportData)
	if err != nil {
		return err
	}

	// Assemble the folder name. The format is:	hex(sha256(teamName))/YYYY-MM-DD
	// The idea behind this is that if we use teams names as folder names, then
	// it would be easy to predict in which folders the reports are stored for
	// each team
	sha := fmt.Sprintf("%x", sha256.Sum256([]byte(d.teamName)))
	d.folder = filepath.Join(sha, reportData.Date)

	// Remove previously generated files and folders and then recreate them.
	err = d.cleanLocalFolders()
	if err != nil {
		return err
	}

	// Generate files for the Overview. The files will be stored in this way:
	// <scan-id>/
	//	  '
	//    '--<scan-id>-overview.html
	//	  '
	//    '--<public-bucket>/
	//	         '
	//           '--<hex(sha256(teamName))>/
	//	                '
	//                  '--<YYYY-MM-DD>/
	//                         '
	//                         '--<Most Vulnerable Assets>.png
	//                         '
	//                         '--<Impact Distribution>.png
	d.Email, err = report.GenerateOverview(d.conf, d.awsConfig, d.folder, reportData, d.teamName, d.teamID, d.scanID)
	if err != nil {
		return err
	}

	// Generate files for the Full Report. The files will be stored in this way:
	// <scan-id>/
	//    '
	//    '--<private-bucket>/
	//           '
	//           '--<hex(sha256(teamName))>/
	//                  '
	//                  '--<YYYY-MM-DD>/
	//                         '
	//                         '--<scan-id>-full-report.html
	//                         '
	//                         '--<script>.js
	//
	// The result will be the the URL in which the Full Report will be available.
	// The Overview HTML will be generated pointing to this link.
	d.URL, err = report.GenerateFullReport(d.conf, d.awsConfig, d.folder, reportData, d.teamName)
	if err != nil {
		return err
	}

	d.Risk = int(reportData.Risk)

	return nil
}

// GenerateLocalFilesFromCheck grabs the check report stored in a file
// and generates the html report using that unique check report.
func (d *DetailedReport) GenerateLocalFilesFromCheck(path string) error {

	reportData, err := vulcan.GetReportDataFromFile(d.conf, d.scanID, path)
	if err != nil {
		return err
	}

	file, err := os.Create(d.teamName + ".json")
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(reportData)
	if err != nil {
		return err
	}

	// Assemble the folder name. The format is:	hex(sha256(teamName))/YYYY-MM-DD
	// The idea behind this is that if we use teams names as folder names, then
	// it would be easy to predict in which folders the reports are stored for
	// each team
	sha := fmt.Sprintf("%x", sha256.Sum256([]byte(d.teamName)))
	d.folder = filepath.Join(sha, reportData.Date)

	// Remove previously generated files and folders and then recreate them.
	err = d.cleanLocalFolders()
	if err != nil {
		return err
	}

	// Generate files for the Full Report. The files will be stored in this way:
	// <scan-id>/
	//    '
	//    '--<private-bucket>/
	//           '
	//           '--<hex(sha256(teamName))>/
	//                  '
	//                  '--<YYYY-MM-DD>/
	//                         '
	//                         '--<scan-id>-full-report.html
	//                         '
	//                         '--<script>.js
	//
	// The result will be the the URL in which the Full Report will be available.
	// The Overview HTML will be generated pointing to this link.
	d.URL, err = report.GenerateFullReport(d.conf, d.awsConfig, d.folder, reportData, d.teamName)
	if err != nil {
		return err
	}

	d.Risk = int(reportData.Risk)

	return nil
}

func (d *DetailedReport) cleanLocalFolders() error {
	err := os.RemoveAll(filepath.Join(d.conf.General.LocalTempDir, d.scanID))
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Join(d.conf.General.LocalTempDir, d.scanID, d.conf.S3.PublicBucket, d.folder), 0700)
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Join(d.conf.General.LocalTempDir, d.scanID, d.conf.S3.PrivateBucket, d.folder), 0700)
	if err != nil {
		return err
	}

	return nil
}

func (d *DetailedReport) UploadFilesToS3() error {
	err := d.uploadBucket(d.conf.S3.PrivateBucket)
	if err != nil {
		return err
	}

	err = d.uploadBucket(d.conf.S3.PublicBucket)
	if err != nil {
		return err
	}

	log.Printf("overview: %v", d.Email)
	log.Printf("full report: %v", d.URL)

	return nil
}

func (d *DetailedReport) uploadBucket(bucket string) error {
	localPath := filepath.Join(d.conf.General.LocalTempDir, d.scanID, bucket, d.folder)
	fd, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer fd.Close()
	files, _ := fd.Readdir(-1)
	for _, file := range files {
		log.Printf("upload: %v/%v", bucket, filepath.Join(d.folder, file.Name()))
		err = d.uploadFile(bucket, filepath.Join(d.folder, file.Name()), localPath, file.Name())
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *DetailedReport) uploadFile(bucket, key, localPath, filename string) error {
	sess, err := session.NewSession(d.awsConfig)
	if err != nil {
		return err
	}
	svc := s3.New(sess)
	localFilename := filepath.Join(localPath, filename)
	contentType := mime.TypeByExtension(filepath.Ext(localFilename))
	body, err := os.ReadFile(localFilename)
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

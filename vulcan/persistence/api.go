package persistence

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
)

//GetDate retrieves the date for a scan.
func GetDate(baseEndpoint, scanID string) (string, error) {
	url := baseEndpoint + "/v1/scans/" + scanID
	resp, err := http.Get(url)
	if err != nil {
		return "", errors.New("Error calling endpoint: " + url + "\n" + err.Error())
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.New("Error calling endpoint: " + url + "\n" + err.Error())
	}
	scan := &Scan{}
	err = json.Unmarshal(body, scan)
	if err != nil {
		return "", errors.New("Error calling endpoint: " + url + "\n" + err.Error())
	}

	date := scan.StartTime.Format("2006-01-02")
	return date, nil
}

//GetChecks retrieves all checks for a scan.
func GetChecks(baseEndpoint, scanID string) ([]Check, error) {
	url := baseEndpoint + "/v1/scans/" + scanID + "/checks?status=FINISHED"
	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.New("Error calling endpoint: " + url + "\n" + err.Error())
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("Error calling endpoint: " + url + "\n" + err.Error())
	}

	checksResp := &Checks{}
	err = json.Unmarshal(body, checksResp)
	if err != nil {
		return nil, errors.New("Error calling endpoint: " + url + "\n" + err.Error())
	}

	checks := checksResp.Checks
	return checks, nil
}

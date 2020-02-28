package results

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/adevinta/vulcan-report"
)

//GetReport retrieves a report stored on vulcan results
func GetReport(baseEndpoint, date, scanID, checkID string) (*report.Report, error) {
	endpoint := baseEndpoint + fmt.Sprintf("/v1/reports/dt=%s/scan=%s/%s.json", date, scanID, checkID)
	//fmt.Printf("Getting results for:%s", endpoint)
	resp, err := http.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	r := &report.Report{}

	err = r.UnmarshalJSONTimeAsString(body)
	if err != nil {
		return nil, err
	}

	return r, nil
}

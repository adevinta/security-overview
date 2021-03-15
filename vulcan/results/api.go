package results

import (
	"io/ioutil"
	"net/http"
	"net/url"

	report "github.com/adevinta/vulcan-report"
)

//GetReport retrieves a report stored on vulcan results
func GetReport(baseEndpoint, rurl string) (*report.Report, error) {
	u, err := url.Parse(baseEndpoint)
	if err != nil {
		return nil, err
	}
	reportURL, err := url.Parse(rurl)
	u.Path = reportURL.Path
	resp, err := http.Get(u.String())
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

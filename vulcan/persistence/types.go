package persistence

import (
	"time"
)

//Scan represents the response from /scan/{id}
type Scan struct {
	ID        string    `json:"id"`
	StartTime time.Time `json:"start_time"`
}

//Checks represents the response from /scan/{id}/checks
type Checks struct {
	Checks []Check `json:"checks"`
}

//Check represents an individual check from Checks
type Check struct {
	ID            string `json:"id"`
	Target        string `json:"target"`
	Status        string `json:"status"`
	Report        string `json:"report"`
	CheckTypeName string `json:"checktype_name"`
}

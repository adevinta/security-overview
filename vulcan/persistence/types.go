package persistence

import (
	"time"
)

//Scan represents the response from /scan/{id}
type Scan struct {
	Scan ScanObject `json:"scan"`
}

//ScanObject is the actual content of a Scan
type ScanObject struct {
	ID        string    `json:"id"`
	Size      int       `json:"size"`
	CreatedAt time.Time `json:"created_at"`
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

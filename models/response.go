package models

type HTTPResponse struct {
	Status  string     `json:"status"`
	Message string     `json:"message"`
	Data    any        `json:"data,omitempty"`
	Error   *HTTPError `json:"error,omitempty"`
}

const (
	STATUS_SUCCESS = "Success"
	STATUS_ERROR   = "Error"
)

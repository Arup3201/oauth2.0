package models

import "time"

type HTTPError struct {
	Code       string    `json:"code"`
	Message    string    `json:"message"`
	Details    string    `json:"details"`
	Timestamp  time.Time `json:"timestamp"`
	Path       string    `json:"path"`
	Suggestion string    `json:"suggestion"`
	Cause      error     `json:"-"`
}

func GenerateHTTPError(code, message, details, suggestion, path string, cause error) *HTTPError {
	return &HTTPError{
		Code:       code,
		Message:    message,
		Details:    details,
		Suggestion: suggestion,
		Timestamp:  time.Now().UTC(),
		Path:       path,
		Cause:      cause,
	}
}

func (err *HTTPError) Error() string {
	if err.Cause != nil {
		return err.Cause.Error()
	}
	return err.Details
}

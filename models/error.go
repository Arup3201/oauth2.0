package models

import (
	"time"
)

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

const (
	ERROR_INVALID_PAYLOAD   = "INVALID_PAYLOAD"
	ERROR_PASSWORD_ENCODING = "MALFORMED_PASSWORD_ENCODING"
	ERROR_INVALID_USER      = "INVALID_USER_EMAIL"
	ERROR_PASSWORD_MISMATCH = "PASSWORD_MISMATCH"
	ERROR_INTERNAL_SERVER   = "INTERNAL_SERVER_FAILED"
)

func InvalidPayloadError(path string, err error) *HTTPError {
	return GenerateHTTPError(
		ERROR_INVALID_PAYLOAD,
		"The incoming data is invalid for registration",
		"Payload contains invalid email or password",
		"Please review your email and password and try with a valid email and password",
		path,
		err,
	)
}

func PasswordEncodingError(path string, err error) *HTTPError {
	return GenerateHTTPError(
		ERROR_PASSWORD_ENCODING,
		"The incoming data encoding is invalid",
		"Payload contains invalid password encoding",
		"Please check with your user-agent to send supported password encoding",
		path,
		err,
	)
}

func UserNotFoundError(path string, err error) *HTTPError {
	return GenerateHTTPError(
		ERROR_INTERNAL_SERVER,
		"The user is not found",
		"There is no user with given user email",
		"Please use the correct user email and try again",
		path,
		err,
	)
}

func PasswordMismatchError(path string, err error) *HTTPError {
	return GenerateHTTPError(
		ERROR_PASSWORD_MISMATCH,
		"Password did not match",
		"User provided a wrong password",
		"Please use the correct user password and try again",
		path,
		err,
	)
}

func InternalServerError(path string, err error) *HTTPError {
	return GenerateHTTPError(
		ERROR_INTERNAL_SERVER,
		"Server failed to register the user",
		"Server failed while adding the user to our database",
		"We are working on our server currently, please come back later for registration",
		path,
		err,
	)
}

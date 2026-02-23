package errs

import (
	"errors"
	"net/http"
)

// Code is an application error code.
type Code string

const (
	InvalidArgument    Code = "invalid_argument"
	NotFound           Code = "not_found"
	FailedPrecondition Code = "failed_precondition"
	PermissionDenied   Code = "permission_denied"
	Unavailable        Code = "unavailable"
	Internal           Code = "internal"
)

// Error is a coded application error.
type Error struct {
	Code    Code
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// New creates a coded error with message.
func New(code Code, message string) error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// Wrap creates a coded error with message and cause.
func Wrap(code Code, message string, cause error) error {
	return &Error{
		Code:    code,
		Message: message,
		Err:     cause,
	}
}

// CodeOf returns the error code, defaulting to internal.
func CodeOf(err error) Code {
	if err == nil {
		return Internal
	}
	var coded *Error
	if errors.As(err, &coded) {
		if coded.Code == "" {
			return Internal
		}
		return coded.Code
	}
	return Internal
}

// MessageOf returns a user-facing error message.
// If the error has no typed wrapper, returns "internal error" to prevent
// leaking raw DB errors, file paths, or connection strings to API responses.
func MessageOf(err error) string {
	if err == nil {
		return string(Internal)
	}
	var coded *Error
	if errors.As(err, &coded) && coded.Message != "" {
		return coded.Message
	}
	return "internal error"
}

// HTTPStatus maps error code to HTTP status.
func HTTPStatus(code Code) int {
	switch code {
	case InvalidArgument:
		return http.StatusBadRequest
	case PermissionDenied:
		return http.StatusForbidden
	case NotFound:
		return http.StatusNotFound
	case FailedPrecondition:
		return http.StatusConflict
	case Unavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

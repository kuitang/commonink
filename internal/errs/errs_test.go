package errs

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"pgregory.net/rapid"
)

func testCodeOf_RoundtripForTypedErrors(t *rapid.T) {
	code := rapid.SampledFrom([]Code{
		InvalidArgument,
		NotFound,
		FailedPrecondition,
		PermissionDenied,
		Unavailable,
		Internal,
	}).Draw(t, "code")
	message := rapid.StringMatching(`[a-zA-Z0-9 _:\-]{1,80}`).Draw(t, "message")

	err := New(code, message)
	if got := CodeOf(err); got != code {
		t.Fatalf("CodeOf(New) mismatch: got=%q want=%q", got, code)
	}
	if got := MessageOf(err); got != message {
		t.Fatalf("MessageOf(New) mismatch: got=%q want=%q", got, message)
	}
}

func TestCodeOf_RoundtripForTypedErrors(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testCodeOf_RoundtripForTypedErrors)
}

func testCodeOfAndMessageOf_WrappedTypedError(t *rapid.T) {
	code := rapid.SampledFrom([]Code{
		InvalidArgument,
		NotFound,
		FailedPrecondition,
		PermissionDenied,
		Unavailable,
		Internal,
	}).Draw(t, "code")
	message := rapid.StringMatching(`[a-zA-Z0-9 _:\-]{1,80}`).Draw(t, "message")
	cause := errors.New(rapid.StringMatching(`[a-zA-Z0-9 _:\-]{1,80}`).Draw(t, "cause"))

	err := Wrap(code, message, cause)
	wrapped := fmt.Errorf("outer: %w", err)

	if got := CodeOf(wrapped); got != code {
		t.Fatalf("CodeOf(wrapped) mismatch: got=%q want=%q", got, code)
	}
	if got := MessageOf(wrapped); got != message {
		t.Fatalf("MessageOf(wrapped) mismatch: got=%q want=%q", got, message)
	}
}

func TestCodeOfAndMessageOf_WrappedTypedError(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testCodeOfAndMessageOf_WrappedTypedError)
}

func testUntypedAndNilFallbacks(t *rapid.T) {
	raw := rapid.StringMatching(`[a-zA-Z0-9 _:\-./]{1,80}`).Draw(t, "raw")
	untyped := errors.New(raw)

	if got := CodeOf(untyped); got != Internal {
		t.Fatalf("CodeOf(untyped) mismatch: got=%q want=%q", got, Internal)
	}
	if got := MessageOf(untyped); got != "internal error" {
		t.Fatalf("MessageOf(untyped) mismatch: got=%q want=%q", got, "internal error")
	}
	if got := CodeOf(nil); got != Internal {
		t.Fatalf("CodeOf(nil) mismatch: got=%q want=%q", got, Internal)
	}
	if got := MessageOf(nil); got != string(Internal) {
		t.Fatalf("MessageOf(nil) mismatch: got=%q want=%q", got, Internal)
	}
}

func TestUntypedAndNilFallbacks(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testUntypedAndNilFallbacks)
}

func testHTTPStatus_Mapping(t *rapid.T) {
	cases := map[Code]int{
		InvalidArgument:    http.StatusBadRequest,
		PermissionDenied:   http.StatusForbidden,
		NotFound:           http.StatusNotFound,
		FailedPrecondition: http.StatusConflict,
		Unavailable:        http.StatusServiceUnavailable,
		Internal:           http.StatusInternalServerError,
	}

	code := rapid.SampledFrom([]Code{
		InvalidArgument,
		PermissionDenied,
		NotFound,
		FailedPrecondition,
		Unavailable,
		Internal,
		Code("unknown_code"),
	}).Draw(t, "code")

	want := http.StatusInternalServerError
	if mapped, ok := cases[code]; ok {
		want = mapped
	}
	if got := HTTPStatus(code); got != want {
		t.Fatalf("HTTPStatus mismatch: code=%q got=%d want=%d", code, got, want)
	}
}

func TestHTTPStatus_Mapping(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testHTTPStatus_Mapping)
}

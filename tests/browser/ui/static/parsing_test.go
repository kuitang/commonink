package browser

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func drawBrowserServiceName(t *rapid.T) string {
	return strings.TrimSpace(rapid.StringMatching(`[a-z][a-z0-9-]{0,20}`).Draw(t, "service_name"))
}

func TestTestFirstServiceName_JSON_Properties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := drawBrowserServiceName(t)
		payload, err := json.Marshal([]map[string]string{
			{"name": ""},
			{"name": name},
		})
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		got := testFirstServiceName(string(payload))
		if got != name {
			t.Fatalf("expected %q, got %q", name, got)
		}
	})
}

func TestTestFirstServiceName_TextFormats_Properties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := drawBrowserServiceName(t)

		bracket := fmt.Sprintf("[name:%s] [status:running]", name)
		if got := testFirstServiceName(bracket); got != name {
			t.Fatalf("expected %q from bracket format, got %q", name, got)
		}

		column := fmt.Sprintf("%s running", name)
		if got := testFirstServiceName(column); got != name {
			t.Fatalf("expected %q from column format, got %q", name, got)
		}
	})
}

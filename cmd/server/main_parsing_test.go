package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func drawServiceName(t *rapid.T) string {
	return strings.TrimSpace(rapid.StringMatching(`[a-z][a-z0-9-]{0,20}`).Draw(t, "service_name"))
}

func TestFirstServiceName_JSONList_Properties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := drawServiceName(t)
		payload, err := json.Marshal([]map[string]string{
			{"name": ""},
			{"name": name},
			{"name": "ignored-after-first"},
		})
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		got := firstServiceName(string(payload))
		if got != name {
			t.Fatalf("expected %q, got %q (payload=%s)", name, got, string(payload))
		}
	})
}

func TestFirstServiceName_JSONObject_Properties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := drawServiceName(t)
		payload, err := json.Marshal(map[string]string{"name": name})
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		got := firstServiceName(string(payload))
		if got != name {
			t.Fatalf("expected %q, got %q (payload=%s)", name, got, string(payload))
		}
	})
}

func TestFirstServiceName_BracketAndColumnFormats_Properties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := drawServiceName(t)

		bracketOutput := fmt.Sprintf("[name:%s] [status:running]", name)
		gotBracket := firstServiceName(bracketOutput)
		if gotBracket != name {
			t.Fatalf("bracket format expected %q, got %q", name, gotBracket)
		}

		columnOutput := fmt.Sprintf("%s running healthy", name)
		gotColumn := firstServiceName(columnOutput)
		if gotColumn != name {
			t.Fatalf("column format expected %q, got %q", name, gotColumn)
		}
	})
}

func TestFirstServiceName_NoServiceSignal_Properties(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := rapid.StringMatching(`[\t ]{0,8}`).Draw(t, "prefix")
		suffix := rapid.StringMatching(`[\t ]{0,8}`).Draw(t, "suffix")
		output := prefix + "no services registered" + suffix

		got := firstServiceName(output)
		if got != "" {
			t.Fatalf("expected empty service name, got %q (output=%q)", got, output)
		}
	})
}

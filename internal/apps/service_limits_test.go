package apps

import (
	"context"
	"path"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func testSanitizePath_ValidRelativePath(t *rapid.T) {
	// Each segment must contain at least one alphanumeric character to be a valid
	// filename (pure "." or ".." are not valid path components).
	p1 := rapid.StringMatching(`[a-zA-Z0-9][a-zA-Z0-9._-]{0,15}`).Draw(t, "p1")
	p2 := rapid.StringMatching(`[a-zA-Z0-9][a-zA-Z0-9._-]{0,15}`).Draw(t, "p2")
	raw := p1 + "/" + p2

	clean, absolute, err := sanitizePath(raw)
	if err != nil {
		t.Fatalf("sanitizePath failed for valid path %q: %v", raw, err)
	}
	if clean == "" || absolute == "" {
		t.Fatalf("sanitizePath returned empty values: clean=%q absolute=%q", clean, absolute)
	}
	if !strings.HasPrefix(absolute, "/home/sprite/") {
		t.Fatalf("absolute path should be rooted at /home/sprite: %q", absolute)
	}
	for _, seg := range strings.Split(path.Clean(clean), "/") {
		if seg == ".." {
			t.Fatalf("clean path still contains traversal segment: %q", clean)
		}
	}
}

func TestSanitizePath_ValidRelativePath(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testSanitizePath_ValidRelativePath)
}

func testSanitizePath_RejectsTraversalOrAbsolute(t *rapid.T) {
	bad := rapid.SampledFrom([]string{
		"",
		"   ",
		"/etc/passwd",
		"../secret",
		"a/../../b",
		"..",
		".",
		`..\windows`,
	}).Draw(t, "bad")

	_, _, err := sanitizePath(bad)
	if err == nil {
		t.Fatalf("expected sanitizePath to reject %q", bad)
	}
}

func TestSanitizePath_RejectsTraversalOrAbsolute(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testSanitizePath_RejectsTraversalOrAbsolute)
}

func TestWriteFiles_RejectsTooManyFilesBeforeBackendCalls(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, _, cleanup := newAppsServiceWithMockSpriteAPI(t, "limits-app", "limits-app-canon", "https://limits-app-canon.sprites.app/")
	defer cleanup()

	files := make([]AppWriteFileInput, maxAppWriteFiles+1)
	for i := range files {
		files[i] = AppWriteFileInput{
			Path:    "file.txt",
			Content: "x",
		}
	}

	_, err := svc.WriteFiles(ctx, "limits-app", files)
	if err == nil {
		t.Fatal("expected error for too many files")
	}
	if !strings.Contains(err.Error(), "must contain <=") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWriteFiles_RejectsDuplicatePaths(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, _, cleanup := newAppsServiceWithMockSpriteAPI(t, "dup-test", "dup-test-canon", "https://dup-test-canon.sprites.app/")
	defer cleanup()

	if _, err := svc.Create(ctx, []string{"dup-test"}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	_, err := svc.WriteFiles(ctx, "dup-test", []AppWriteFileInput{
		{Path: "app.py", Content: "print(1)\n"},
		{Path: "./app.py", Content: "print(2)\n"},
	})
	if err == nil {
		t.Fatal("expected duplicate path validation error")
	}
	if !strings.Contains(err.Error(), "duplicate file path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunExec_RejectsTimeoutAboveMaxBeforeCommandExecution(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, _, cleanup := newAppsServiceWithMockSpriteAPI(t, "timeout-app", "timeout-app-canon", "https://timeout-app-canon.sprites.app/")
	defer cleanup()

	if _, err := svc.Create(ctx, []string{"timeout-app"}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	_, err := svc.RunExec(ctx, "timeout-app", []string{"echo", "ok"}, maxExecTimeoutSeconds+1)
	if err == nil {
		t.Fatal("expected timeout validation error")
	}
	if !strings.Contains(err.Error(), "timeout_seconds must be <=") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunExec_RejectsEmptyArgv(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, _, cleanup := newAppsServiceWithMockSpriteAPI(t, "empty-argv-app", "empty-argv-app-canon", "https://empty-argv-app-canon.sprites.app/")
	defer cleanup()

	_, err := svc.RunExec(ctx, "empty-argv-app", []string{}, 10)
	if err == nil {
		t.Fatal("expected error for empty argv")
	}
	if !strings.Contains(err.Error(), "argv must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunExec_ArgvTotalSizeLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, _, cleanup := newAppsServiceWithMockSpriteAPI(t, "argv-size-app", "argv-size-app-canon", "https://argv-size-app-canon.sprites.app/")
	defer cleanup()

	rapid.Check(t, func(t *rapid.T) {
		numArgs := rapid.IntRange(1, 10).Draw(t, "numArgs")
		perArgSize := (maxExecArgvBytes / numArgs) + 1
		argv := make([]string, numArgs)
		for i := range argv {
			argv[i] = strings.Repeat("x", perArgSize)
		}

		_, err := svc.RunExec(ctx, "argv-size-app", argv, 10)
		if err == nil {
			t.Fatal("expected error for oversized argv")
		}
		if !strings.Contains(err.Error(), "total argv size must be <=") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func testCappedOutputBuffer_TruncatesAtConfiguredLimit(t *rapid.T) {
	maxBytes := rapid.IntRange(1, 128).Draw(t, "max_bytes")
	buf := newCappedOutputBuffer(maxBytes)

	extra := rapid.IntRange(1, 256).Draw(t, "extra_bytes")
	payload := strings.Repeat("x", maxBytes+extra)
	if _, err := buf.Write([]byte(payload)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if len(buf.String()) > maxBytes {
		t.Fatalf("buffer exceeded maxBytes: got=%d max=%d", len(buf.String()), maxBytes)
	}
	if !buf.Truncated() {
		t.Fatal("expected truncated buffer for oversized payload")
	}
}

func TestCappedOutputBuffer_TruncatesAtConfiguredLimit(t *testing.T) {
	t.Parallel()
	rapid.Check(t, testCappedOutputBuffer_TruncatesAtConfiguredLimit)
}

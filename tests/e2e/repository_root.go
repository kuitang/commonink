package e2e

import (
	"path/filepath"
	"runtime"
)

func repositoryRoot() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("cannot resolve repository root in tests/e2e")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

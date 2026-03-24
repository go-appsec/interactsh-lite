package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunHealthCheck(t *testing.T) {
	t.Parallel()

	t.Run("basic_output", func(t *testing.T) {
		var buf bytes.Buffer
		configPath := filepath.Join(t.TempDir(), "config.yaml")

		runHealthCheck(&buf, "1.0.0-test", configPath)
		output := buf.String()

		assert.Contains(t, output, "Version: 1.0.0-test")
		assert.Contains(t, output, "Operating System: "+runtime.GOOS)
		assert.Contains(t, output, "Architecture: "+runtime.GOARCH)
		assert.Contains(t, output, "Go Version: "+runtime.Version())
		assert.Contains(t, output, "Compiler: "+runtime.Compiler)
		assert.Contains(t, output, "Config file")
	})

	t.Run("config_file_exists", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(configPath, []byte("server: test.com\n"), 0600))

		var buf bytes.Buffer
		runHealthCheck(&buf, "1.0.0", configPath)
		output := buf.String()

		assert.Contains(t, output, "Read => Ok")
		assert.NotContains(t, output, "file does not exist")
	})
}

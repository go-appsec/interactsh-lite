package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunHealthCheck(t *testing.T) {
	t.Parallel()

	t.Run("basic_output", func(t *testing.T) {
		var buf bytes.Buffer
		configPath := filepath.Join(t.TempDir(), "config.yaml")

		RunHealthCheck(&buf, "1.0.0-test", configPath)
		output := buf.String()

		assert.Contains(t, output, "Version: 1.0.0-test")
		assert.Contains(t, output, "Operative System: "+runtime.GOOS)
		assert.Contains(t, output, "Architecture: "+runtime.GOARCH)
		assert.Contains(t, output, "Go Version: "+runtime.Version())
		assert.Contains(t, output, "Compiler: "+runtime.Compiler)
		assert.Contains(t, output, "Config file")
	})

	t.Run("config_file_exists", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(configPath, []byte("server: test.com\n"), 0600))

		var buf bytes.Buffer
		RunHealthCheck(&buf, "1.0.0", configPath)
		output := buf.String()

		assert.Contains(t, output, "Read => Ok")
		assert.NotContains(t, output, "file does not exist")
	})
}

func TestHealthCheckOutput(t *testing.T) {
	// This test verifies the general structure of the output without making real network calls
	t.Parallel()

	var buf bytes.Buffer
	configPath := filepath.Join(t.TempDir(), "test-config.yaml")

	RunHealthCheck(&buf, "0.1.0", configPath)
	output := buf.String()
	lines := strings.Split(output, "\n")

	assert.GreaterOrEqual(t, len(lines), 5)

	assert.True(t, strings.HasPrefix(lines[0], "Version:"))

	var hasOS, hasArch, hasGoVersion, hasCompiler bool
	for _, line := range lines {
		if strings.HasPrefix(line, "Operative System:") {
			hasOS = true
		} else if strings.HasPrefix(line, "Architecture:") {
			hasArch = true
		} else if strings.HasPrefix(line, "Go Version:") {
			hasGoVersion = true
		} else if strings.HasPrefix(line, "Compiler:") {
			hasCompiler = true
		}
	}
	assert.True(t, hasOS)
	assert.True(t, hasArch)
	assert.True(t, hasGoVersion)
	assert.True(t, hasCompiler)
}

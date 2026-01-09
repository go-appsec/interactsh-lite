package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandPatterns(t *testing.T) {
	t.Parallel()

	t.Run("empty_input", func(t *testing.T) {
		result, err := expandPatterns(nil)
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("comma_separated", func(t *testing.T) {
		result, err := expandPatterns([]string{"a,b,c"})
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b", "c"}, result)
	})

	t.Run("multiple_values", func(t *testing.T) {
		result, err := expandPatterns([]string{"foo", "bar,baz"})
		require.NoError(t, err)
		assert.Equal(t, []string{"foo", "bar", "baz"}, result)
	})

	t.Run("patterns_from_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "patterns.txt")
		content := "pattern1\npattern2\npattern3\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))

		result, err := expandPatterns([]string{path})
		require.NoError(t, err)
		assert.Equal(t, []string{"pattern1", "pattern2", "pattern3"}, result)
	})

	t.Run("file_with_comments_and_blanks", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "patterns.txt")
		content := "# comment line\npattern1\n\n  \n# another comment\npattern2\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))

		result, err := expandPatterns([]string{path})
		require.NoError(t, err)
		assert.Equal(t, []string{"pattern1", "pattern2"}, result)
	})

	t.Run("mixed_file_and_values", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "patterns.txt")
		require.NoError(t, os.WriteFile(path, []byte("from_file\n"), 0600))

		result, err := expandPatterns([]string{"inline", path, "another,value"})
		require.NoError(t, err)
		assert.Equal(t, []string{"inline", "from_file", "another", "value"}, result)
	})
}

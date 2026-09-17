// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionCmd_Output(t *testing.T) {
	_, buf := setupTestCmd(t)

	Version = "1.2.3"
	GitCommit = "abc1234"
	BuildDate = "2026-03-01"

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"version"})
	err := cmd.Execute()
	assert.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "falcon 1.2.3")
	assert.Contains(t, output, "abc1234")
	assert.Contains(t, output, "2026-03-01")
}

func TestVersionCmd_DevDefaults(t *testing.T) {
	_, buf := setupTestCmd(t)

	// Reset to dev defaults
	Version = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"version"})
	err := cmd.Execute()
	assert.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "falcon dev")
	assert.Contains(t, output, "unknown")
}

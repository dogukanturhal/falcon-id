// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPrinter(format Format, noColor bool) (*Printer, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	p := NewPrinter(format, noColor)
	p.SetWriter(buf)
	return p, buf
}

func TestNewPrinter(t *testing.T) {
	p := NewPrinter(FormatTable, false)
	assert.NotNil(t, p)
	assert.Equal(t, FormatTable, p.format)
	assert.False(t, p.noColor)
}

func TestPrintTable_OutputsHeadersAndRows(t *testing.T) {
	p, buf := newTestPrinter(FormatTable, true)

	headers := []string{"ID", "NAME", "STATUS"}
	rows := [][]string{
		{"u-1", "alice", "active"},
		{"u-2", "bob", "inactive"},
	}

	p.PrintTable(headers, rows)

	output := buf.String()
	assert.Contains(t, output, "ID")
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "STATUS")
	assert.Contains(t, output, "alice")
	assert.Contains(t, output, "bob")
	assert.Contains(t, output, "active")
	assert.Contains(t, output, "inactive")
	// Separator line
	assert.Contains(t, output, "--")
}

func TestPrintTable_SeparatorMatchesHeaderLength(t *testing.T) {
	p, buf := newTestPrinter(FormatTable, true)

	headers := []string{"ID", "EMAIL"}
	p.PrintTable(headers, nil)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2) // header + separator, no data rows
	// Separator should have dashes matching header lengths
	assert.Contains(t, lines[1], "--")
	assert.Contains(t, lines[1], "-----")
}

func TestPrintTable_EmptyRows(t *testing.T) {
	p, buf := newTestPrinter(FormatTable, true)

	headers := []string{"ID", "NAME"}
	p.PrintTable(headers, [][]string{})

	output := buf.String()
	assert.Contains(t, output, "ID")
	assert.Contains(t, output, "NAME")
}

func TestPrintJSON_OutputsValidJSON(t *testing.T) {
	p, buf := newTestPrinter(FormatJSON, false)

	data := map[string]interface{}{
		"users": []map[string]string{
			{"id": "u1", "name": "alice"},
		},
		"total": 1,
	}

	err := p.PrintJSON(data)
	require.NoError(t, err)

	// Verify it's valid JSON
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &parsed))
	assert.Equal(t, float64(1), parsed["total"])
}

func TestPrintJSON_FormattedWithIndent(t *testing.T) {
	p, buf := newTestPrinter(FormatJSON, false)

	data := map[string]string{"key": "value"}
	err := p.PrintJSON(data)
	require.NoError(t, err)

	// Should have indentation (2 spaces)
	assert.Contains(t, buf.String(), "  \"key\"")
}

func TestPrint_SelectsTableFormatByDefault(t *testing.T) {
	p, buf := newTestPrinter(FormatTable, true)

	headers := []string{"ID"}
	rows := [][]string{{"val-1"}}
	data := map[string]string{"id": "val-1"}

	err := p.Print(headers, rows, data)
	require.NoError(t, err)

	// Should output table format (contains "ID" header, not JSON braces)
	output := buf.String()
	assert.Contains(t, output, "ID")
	assert.NotContains(t, output, "{")
}

func TestPrint_SelectsJSONFormat(t *testing.T) {
	p, buf := newTestPrinter(FormatJSON, false)

	headers := []string{"ID"}
	rows := [][]string{{"val-1"}}
	data := map[string]string{"id": "val-1"}

	err := p.Print(headers, rows, data)
	require.NoError(t, err)

	// Should output JSON format
	output := buf.String()
	assert.Contains(t, output, "{")
	assert.Contains(t, output, "val-1")
}

func TestBadge_ColorCodes(t *testing.T) {
	p, _ := newTestPrinter(FormatTable, false)

	tests := []struct {
		status   string
		colorSeq string
	}{
		{"active", "\033[32m"},
		{"healthy", "\033[32m"},
		{"ok", "\033[32m"},
		{"up", "\033[32m"},
		{"inactive", "\033[33m"},
		{"disabled", "\033[33m"},
		{"suspended", "\033[33m"},
		{"error", "\033[31m"},
		{"down", "\033[31m"},
		{"unhealthy", "\033[31m"},
		{"unknown", "\033[37m"},
		{"pending", "\033[37m"},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			badge := p.Badge(tt.status)
			assert.Contains(t, badge, tt.colorSeq, "badge for %q should contain color sequence", tt.status)
			assert.Contains(t, badge, tt.status)
		})
	}
}

func TestBadge_NoColorMode(t *testing.T) {
	p, _ := newTestPrinter(FormatTable, true)

	tests := []string{"active", "inactive", "error", "pending", "ok"}
	for _, status := range tests {
		t.Run(status, func(t *testing.T) {
			badge := p.Badge(status)
			assert.Equal(t, "["+status+"]", badge)
			// Should not contain ANSI codes
			assert.NotContains(t, badge, "\033[")
		})
	}
}

func TestBadge_CaseInsensitive(t *testing.T) {
	p, _ := newTestPrinter(FormatTable, false)

	// Both uppercase and lowercase should get the same ANSI color code (green for active)
	badge1 := p.Badge("ACTIVE")
	badge2 := p.Badge("active")
	// Both should contain the green ANSI sequence
	assert.Contains(t, badge1, "\033[32m")
	assert.Contains(t, badge2, "\033[32m")
}

func TestPrintMessage(t *testing.T) {
	p, buf := newTestPrinter(FormatTable, true)

	p.PrintMessage("hello world")
	assert.Equal(t, "hello world\n", buf.String())
}

func TestPrintSuccess_NoColor(t *testing.T) {
	p, buf := newTestPrinter(FormatTable, true)

	p.PrintSuccess("operation completed")
	assert.Equal(t, "[OK] operation completed\n", buf.String())
}

func TestPrintSuccess_WithColor(t *testing.T) {
	p, buf := newTestPrinter(FormatTable, false)

	p.PrintSuccess("operation completed")
	output := buf.String()
	assert.Contains(t, output, "\033[32m")
	assert.Contains(t, output, "operation completed")
}

func TestPrintError_NoColor(t *testing.T) {
	p, buf := newTestPrinter(FormatTable, true)

	p.PrintError("something went wrong")
	assert.Equal(t, "[ERROR] something went wrong\n", buf.String())
}

func TestPrintError_WithColor(t *testing.T) {
	p, buf := newTestPrinter(FormatTable, false)

	p.PrintError("something went wrong")
	output := buf.String()
	assert.Contains(t, output, "\033[31m")
	assert.Contains(t, output, "something went wrong")
}

func TestSetWriter_OverridesDefault(t *testing.T) {
	p := NewPrinter(FormatTable, true)
	buf := &bytes.Buffer{}
	p.SetWriter(buf)

	p.PrintMessage("test message")
	assert.Equal(t, "test message\n", buf.String())
}

func TestPrintTable_MultipleColumns_Aligned(t *testing.T) {
	p, buf := newTestPrinter(FormatTable, true)

	headers := []string{"ID", "USERNAME", "EMAIL", "STATUS"}
	rows := [][]string{
		{"1", "alice", "alice@test.com", "active"},
		{"2", "bob-with-longer-name", "bob@example.org", "inactive"},
	}

	p.PrintTable(headers, rows)

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	// Should have header + separator + 2 data rows = 4 lines
	assert.Len(t, lines, 4)
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package output provides CLI output formatting utilities.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

// Format represents the output format.
type Format string

const (
	// FormatTable outputs data as an aligned table.
	FormatTable Format = "table"
	// FormatJSON outputs data as formatted JSON.
	FormatJSON Format = "json"
)

// Printer handles formatted output for the CLI.
type Printer struct {
	format  Format
	writer  io.Writer
	noColor bool
}

// NewPrinter creates a new Printer with the given format and color settings.
func NewPrinter(format Format, noColor bool) *Printer {
	return &Printer{
		format:  format,
		writer:  os.Stdout,
		noColor: noColor,
	}
}

// SetWriter allows overriding the output writer (useful for testing).
func (p *Printer) SetWriter(w io.Writer) {
	p.writer = w
}

// PrintJSON outputs data as indented JSON.
func (p *Printer) PrintJSON(data interface{}) error {
	enc := json.NewEncoder(p.writer)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// PrintTable outputs data as an aligned table with headers and a separator row.
func (p *Printer) PrintTable(headers []string, rows [][]string) {
	w := tabwriter.NewWriter(p.writer, 0, 0, 2, ' ', 0)
	// Header row
	_, _ = fmt.Fprintln(w, strings.Join(headers, "\t"))
	// Separator
	sep := make([]string, len(headers))
	for i, h := range headers {
		sep[i] = strings.Repeat("-", len(h))
	}
	_, _ = fmt.Fprintln(w, strings.Join(sep, "\t"))
	// Data rows
	for _, row := range rows {
		_, _ = fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	_ = w.Flush()
}

// Badge returns a colored status indicator, or a plain bracket notation when noColor is set.
func (p *Printer) Badge(status string) string {
	if p.noColor {
		return "[" + status + "]"
	}
	switch strings.ToLower(status) {
	case "active", "healthy", "ok", "up":
		return "\033[32m●\033[0m " + status // green
	case "inactive", "disabled", "suspended":
		return "\033[33m●\033[0m " + status // yellow
	case "error", "down", "unhealthy":
		return "\033[31m●\033[0m " + status // red
	default:
		return "\033[37m●\033[0m " + status // white/gray
	}
}

// Print auto-selects table or JSON output based on the printer's configured format.
func (p *Printer) Print(headers []string, rows [][]string, jsonData interface{}) error {
	if p.format == FormatJSON {
		return p.PrintJSON(jsonData)
	}
	p.PrintTable(headers, rows)
	return nil
}

// PrintMessage prints a plain message line.
func (p *Printer) PrintMessage(msg string) {
	_, _ = fmt.Fprintln(p.writer, msg)
}

// PrintSuccess prints a success message with a green checkmark (or [OK] in no-color mode).
func (p *Printer) PrintSuccess(msg string) {
	if p.noColor {
		_, _ = fmt.Fprintf(p.writer, "[OK] %s\n", msg)
	} else {
		_, _ = fmt.Fprintf(p.writer, "\033[32m✓\033[0m %s\n", msg)
	}
}

// PrintError prints an error message with a red cross (or [ERROR] in no-color mode).
func (p *Printer) PrintError(msg string) {
	if p.noColor {
		_, _ = fmt.Fprintf(p.writer, "[ERROR] %s\n", msg)
	} else {
		_, _ = fmt.Fprintf(p.writer, "\033[31m✗\033[0m %s\n", msg)
	}
}

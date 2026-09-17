// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const siemContentTypePlainText = "text/plain; charset=utf-8"

// SIEMFormatter is the interface that all SIEM format encoders must implement.
type SIEMFormatter interface {
	// FormatThreatEvent encodes a ThreatEvent into the target wire format.
	FormatThreatEvent(event *models.ThreatEvent) ([]byte, error)
	// FormatAuditLog encodes an audit log entry into the target wire format.
	FormatAuditLog(entry map[string]interface{}) ([]byte, error)
	// ContentType returns the MIME type for this format.
	ContentType() string
}

// NewSIEMFormatter returns the appropriate formatter for the given export_format string.
// Unknown formats fall back to JSONFormatter.
func NewSIEMFormatter(format string) SIEMFormatter {
	switch format {
	case "cef":
		return &CEFFormatter{}
	case "syslog_rfc5424":
		return &SyslogFormatter{Facility: 16} // LOCAL0
	case "leef":
		return &LEEFFormatter{}
	default:
		return &JSONFormatter{}
	}
}

// ---------------------------------------------------------------------------
// JSONFormatter — existing behaviour, kept for backward compatibility
// ---------------------------------------------------------------------------

// JSONFormatter encodes events as JSON objects.
type JSONFormatter struct{}

// FormatThreatEvent encodes a ThreatEvent as JSON.
func (f *JSONFormatter) FormatThreatEvent(event *models.ThreatEvent) ([]byte, error) {
	return json.Marshal(event.ToResponse())
}

// FormatAuditLog encodes an audit log entry as JSON.
func (f *JSONFormatter) FormatAuditLog(entry map[string]interface{}) ([]byte, error) {
	return json.Marshal(entry)
}

// ContentType returns "application/json".
func (f *JSONFormatter) ContentType() string { return "application/json" }

// ---------------------------------------------------------------------------
// CEFFormatter — ArcSight Common Event Format
// ---------------------------------------------------------------------------

// CEFFormatter encodes events as ArcSight CEF (Common Event Format) v0 strings.
//
// Format:
//
//	CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
type CEFFormatter struct{}

// FormatThreatEvent encodes a ThreatEvent as a CEF string.
func (f *CEFFormatter) FormatThreatEvent(event *models.ThreatEvent) ([]byte, error) {
	severity := cefSeverity(string(event.Severity))
	ext := strings.Builder{}
	fmt.Fprintf(&ext, "rt=%s", event.CreatedAt.UTC().Format(time.RFC3339))
	if event.SourceIP != nil {
		fmt.Fprintf(&ext, " src=%s", event.SourceIP.String())
	}
	if event.UserID != nil {
		fmt.Fprintf(&ext, " duid=%s", event.UserID.String())
	}
	if event.TenantID != nil {
		fmt.Fprintf(&ext, " cs1=%s cs1Label=tenantId", event.TenantID.String())
	}
	fmt.Fprintf(&ext, " cs2=%s cs2Label=status", string(event.Status))
	fmt.Fprintf(&ext, " externalId=%s", event.ID.String())

	line := fmt.Sprintf("CEF:0|HexxLock|Falcon-ID|1.0|%s|%s|%d|%s",
		cefEscape(event.EventType),
		cefEscape(event.EventType),
		severity,
		ext.String(),
	)
	return []byte(line), nil
}

// FormatAuditLog encodes an audit log entry as a CEF string.
func (f *CEFFormatter) FormatAuditLog(entry map[string]interface{}) ([]byte, error) {
	action, _ := entry["action"].(string)
	ext := strings.Builder{}
	if ts, ok := entry["created_at"]; ok {
		fmt.Fprintf(&ext, "rt=%v", ts)
	}
	if uid, ok := entry["user_id"]; ok {
		fmt.Fprintf(&ext, " duid=%v", uid)
	}
	if ip, ok := entry["ip_address"]; ok {
		fmt.Fprintf(&ext, " src=%v", ip)
	}
	if id, ok := entry["id"]; ok {
		fmt.Fprintf(&ext, " externalId=%v", id)
	}

	line := fmt.Sprintf("CEF:0|HexxLock|Falcon-ID|1.0|audit.%s|Audit: %s|3|%s",
		cefEscape(action),
		cefEscape(action),
		ext.String(),
	)
	return []byte(line), nil
}

// ContentType returns "text/plain" (CEF is a text format).
func (f *CEFFormatter) ContentType() string { return siemContentTypePlainText }

// cefSeverity maps Falcon-ID severity strings to CEF severity integers (0-10).
func cefSeverity(s string) int {
	switch s {
	case "low":
		return 3
	case string(SecuritySeverityMedium):
		return 5
	case string(SecuritySeverityHigh):
		return 8
	case string(SecuritySeverityCritical):
		return 10
	}
	return 3
}

// cefEscape escapes CEF pipe and backslash characters in field values.
func cefEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return s
}

// ---------------------------------------------------------------------------
// SyslogFormatter — RFC 5424
// ---------------------------------------------------------------------------

// SyslogFormatter encodes events as RFC 5424 syslog messages.
type SyslogFormatter struct {
	// Facility is the syslog facility code (0-23).  16 = local0.
	Facility int
}

// FormatThreatEvent encodes a ThreatEvent as an RFC 5424 syslog message.
func (f *SyslogFormatter) FormatThreatEvent(event *models.ThreatEvent) ([]byte, error) {
	pri := f.Facility*8 + syslogSeverity(string(event.Severity))
	timestamp := event.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z")
	hostname := serviceNameFalconID
	appName := "threat-detector"
	msgID := event.EventType

	// Structured data element
	sd := fmt.Sprintf(`[falconid@12345 eventId="%s" severity="%s" status="%s"]`,
		event.ID.String(), string(event.Severity), string(event.Status))

	msg, _ := json.Marshal(event.ToResponse())

	line := fmt.Sprintf("<%d>1 %s %s %s - %s %s %s",
		pri, timestamp, hostname, appName, msgID, sd, string(msg))
	return []byte(line), nil
}

// FormatAuditLog encodes an audit log entry as an RFC 5424 syslog message.
func (f *SyslogFormatter) FormatAuditLog(entry map[string]interface{}) ([]byte, error) {
	pri := f.Facility*8 + 6 // informational
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	hostname := serviceNameFalconID
	appName := "audit-log"
	action, _ := entry["action"].(string)
	msgID := "audit." + action

	sd := "-"
	if id, ok := entry["id"]; ok {
		sd = fmt.Sprintf(`[auditlog@12345 eventId="%v"]`, id)
	}

	msg, _ := json.Marshal(entry)
	line := fmt.Sprintf("<%d>1 %s %s %s - %s %s %s",
		pri, timestamp, hostname, appName, msgID, sd, string(msg))
	return []byte(line), nil
}

// ContentType returns "text/plain" (syslog is a text format).
func (f *SyslogFormatter) ContentType() string { return siemContentTypePlainText }

// syslogSeverity maps Falcon-ID severity strings to RFC 5424 severity codes.
func syslogSeverity(s string) int {
	switch s {
	case "low":
		return 6 // informational
	case string(SecuritySeverityMedium):
		return 4 // warning
	case string(SecuritySeverityHigh):
		return 3 // error
	case string(SecuritySeverityCritical):
		return 2 // critical
	}
	return 6
}

// ---------------------------------------------------------------------------
// LEEFFormatter — IBM QRadar Log Event Extended Format
// ---------------------------------------------------------------------------

// LEEFFormatter encodes events in IBM QRadar LEEF 2.0 format.
type LEEFFormatter struct{}

// FormatThreatEvent encodes a ThreatEvent as a LEEF 2.0 string.
func (f *LEEFFormatter) FormatThreatEvent(event *models.ThreatEvent) ([]byte, error) {
	fields := fmt.Sprintf("devTime=%s\tseverity=%s\tstatus=%s\teventId=%s",
		event.CreatedAt.UTC().Format(time.RFC3339),
		string(event.Severity),
		string(event.Status),
		event.ID.String(),
	)
	if event.SourceIP != nil {
		fields += "\tsrc=" + event.SourceIP.String()
	}
	if event.UserID != nil {
		fields += "\tusrName=" + event.UserID.String()
	}

	line := fmt.Sprintf("LEEF:2.0|HexxLock|Falcon-ID|1.0|%s|^|%s",
		leefEscape(event.EventType), fields)
	return []byte(line), nil
}

// FormatAuditLog encodes an audit log entry as a LEEF 2.0 string.
func (f *LEEFFormatter) FormatAuditLog(entry map[string]interface{}) ([]byte, error) {
	action, _ := entry["action"].(string)
	fields := strings.Builder{}
	if ts, ok := entry["created_at"]; ok {
		fmt.Fprintf(&fields, "devTime=%v\t", ts)
	}
	if uid, ok := entry["user_id"]; ok {
		fmt.Fprintf(&fields, "usrName=%v\t", uid)
	}
	if id, ok := entry["id"]; ok {
		fmt.Fprintf(&fields, "eventId=%v", id)
	}

	line := fmt.Sprintf("LEEF:2.0|HexxLock|Falcon-ID|1.0|audit.%s|^|%s",
		leefEscape(action), fields.String())
	return []byte(line), nil
}

// ContentType returns "text/plain" (LEEF is a text format).
func (f *LEEFFormatter) ContentType() string { return siemContentTypePlainText }

// leefEscape escapes LEEF pipe characters in field values.
func leefEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

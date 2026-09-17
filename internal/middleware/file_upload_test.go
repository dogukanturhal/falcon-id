// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildFileUploadRouter returns a router with ValidateFileUpload middleware applied
// using the provided config.
func buildFileUploadRouter(cfg FileUploadConfig) *gin.Engine {
	m := NewFileUploadMiddlewareWithConfig(cfg)

	_, router := gin.CreateTestContext(httptest.NewRecorder())
	router.Use(m.ValidateFileUpload())
	router.POST("/upload", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return router
}

// createMultipartRequest builds a multipart/form-data request with a single
// file field named "file".
func createMultipartRequest(t *testing.T, fieldName, filename, _ string, content []byte) *http.Request {
	t.Helper()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile(fieldName, filename)
	require.NoError(t, err)

	_, err = io.Copy(part, bytes.NewReader(content))
	require.NoError(t, err)

	require.NoError(t, writer.Close())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

// createMultipartRequestWithContentTypeOverride builds a multipart/form-data
// request where the part Content-Type header is set explicitly.
func createMultipartRequestWithContentTypeOverride(t *testing.T, fieldName, filename, partContentType string, content []byte) *http.Request { //nolint:unparam // fieldName is always "file" currently but kept for flexibility
	t.Helper()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	header := make(map[string][]string)
	header["Content-Disposition"] = []string{fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fieldName, filename)}
	header["Content-Type"] = []string{partContentType}

	part, err := writer.CreatePart(header)
	require.NoError(t, err)

	_, err = io.Copy(part, bytes.NewReader(content))
	require.NoError(t, err)

	require.NoError(t, writer.Close())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

// TestFileUpload_NonMultipartRequestPassesThrough verifies that the middleware
// ignores requests that are not multipart/form-data.
func TestFileUpload_NonMultipartRequestPassesThrough(t *testing.T) {
	router := buildFileUploadRouter(DefaultFileUploadConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/upload", strings.NewReader(`{"key":"value"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"non-multipart request must pass through without modification")
}

// TestFileUpload_ValidPDFFile verifies that a valid PDF upload is accepted.
func TestFileUpload_ValidPDFFile(t *testing.T) {
	cfg := DefaultFileUploadConfig()
	cfg.RequireMimeValidation = false // disable magic-byte check for unit tests
	router := buildFileUploadRouter(cfg)

	// Minimal valid PDF header.
	pdfContent := []byte("%PDF-1.4 test content here")

	w := httptest.NewRecorder()
	req := createMultipartRequestWithContentTypeOverride(t, "file", "document.pdf", "application/pdf", pdfContent)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestFileUpload_BlockedExtensionIsRejected verifies that a .exe upload is
// blocked regardless of content.
func TestFileUpload_BlockedExtensionIsRejected(t *testing.T) {
	cfg := DefaultFileUploadConfig()
	cfg.RequireMimeValidation = false
	router := buildFileUploadRouter(cfg)

	w := httptest.NewRecorder()
	req := createMultipartRequestWithContentTypeOverride(t, "file", "malware.exe", "application/octet-stream", []byte("MZ binary"))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"blocked file extension (.exe) must be rejected")
}

// TestFileUpload_BlockedScriptExtensionIsRejected verifies .php is also blocked.
func TestFileUpload_BlockedScriptExtensionIsRejected(t *testing.T) {
	cfg := DefaultFileUploadConfig()
	cfg.RequireMimeValidation = false
	router := buildFileUploadRouter(cfg)

	w := httptest.NewRecorder()
	req := createMultipartRequestWithContentTypeOverride(t, "file", "shell.php", "text/plain", []byte("<?php echo 'hello'; ?>"))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"blocked extension (.php) must be rejected")
}

// TestFileUpload_TotalSizeLimitEnforced verifies that uploads exceeding MaxTotalSize
// are rejected. The middleware returns 413 Request Entity Too Large for this case.
func TestFileUpload_TotalSizeLimitEnforced(t *testing.T) {
	cfg := DefaultFileUploadConfig()
	cfg.MaxFileSize = 1024 // 1 KiB per file
	cfg.MaxTotalSize = 50  // 50 bytes total — multipart overhead alone exceeds this
	cfg.RequireMimeValidation = false

	m := NewFileUploadMiddlewareWithConfig(cfg)

	_, router := gin.CreateTestContext(httptest.NewRecorder())
	router.Use(m.ValidateFileUpload())
	router.POST("/upload", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// 200 bytes of content easily exceeds the 50-byte MaxTotalSize limit.
	largeContent := bytes.Repeat([]byte("A"), 200)

	w := httptest.NewRecorder()
	req := createMultipartRequest(t, "file", "big.txt", "text/plain", largeContent)
	router.ServeHTTP(w, req)

	// Middleware returns 413 when total body exceeds MaxTotalSize.
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code,
		"total upload size exceeding MaxTotalSize must return 413")
}

// TestFileUpload_FileSizeLimitEnforced verifies that individual files exceeding
// MaxFileSize (but within MaxTotalSize) are rejected with 400 Bad Request.
func TestFileUpload_FileSizeLimitEnforced(t *testing.T) {
	cfg := DefaultFileUploadConfig()
	// MaxFileSize small, MaxTotalSize large so parsing succeeds but per-file
	// validation catches the oversize file.
	cfg.MaxFileSize = 10
	cfg.MaxTotalSize = 50 * 1024 * 1024
	cfg.AllowedExtensions = []string{".txt"}
	cfg.AllowedMimeTypes = []string{"text/plain"}
	cfg.RequireMimeValidation = false

	m := NewFileUploadMiddlewareWithConfig(cfg)

	_, router := gin.CreateTestContext(httptest.NewRecorder())
	router.Use(m.ValidateFileUpload())
	router.POST("/upload", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// 20 bytes — exceeds MaxFileSize of 10.
	largeContent := bytes.Repeat([]byte("A"), 20)

	w := httptest.NewRecorder()
	req := createMultipartRequestWithContentTypeOverride(t, "file", "big.txt", "text/plain", largeContent)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"individual file exceeding MaxFileSize must be rejected with 400")
}

// TestFileUpload_PathTraversalFilenameRejected verifies that filenames with ".."
// are rejected to prevent path traversal.
func TestFileUpload_PathTraversalFilenameRejected(t *testing.T) {
	cfg := DefaultFileUploadConfig()
	cfg.RequireMimeValidation = false
	router := buildFileUploadRouter(cfg)

	w := httptest.NewRecorder()
	req := createMultipartRequestWithContentTypeOverride(t, "file", "../../../etc/passwd", "text/plain", []byte("data"))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"path traversal filename must be rejected")
}

// TestFileUpload_HiddenFilenameRejected verifies that filenames starting with a
// dot (hidden files) are rejected.
func TestFileUpload_HiddenFilenameRejected(t *testing.T) {
	cfg := DefaultFileUploadConfig()
	cfg.RequireMimeValidation = false
	router := buildFileUploadRouter(cfg)

	w := httptest.NewRecorder()
	req := createMultipartRequestWithContentTypeOverride(t, "file", ".htaccess", "text/plain", []byte("Options -Indexes"))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"hidden filename must be rejected")
}

// TestFileUpload_NotAllowedExtensionRejected verifies that an extension not in
// AllowedExtensions (with a non-empty allow-list) is rejected.
func TestFileUpload_NotAllowedExtensionRejected(t *testing.T) {
	cfg := DefaultFileUploadConfig()
	cfg.AllowedExtensions = []string{".pdf"} // only PDFs permitted
	cfg.RequireMimeValidation = false
	router := buildFileUploadRouter(cfg)

	w := httptest.NewRecorder()
	req := createMultipartRequestWithContentTypeOverride(t, "file", "image.png", "image/png", []byte("fake png"))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"extension not in AllowedExtensions must be rejected")
}

// TestFileUpload_EmptyMultipartFormPassesThrough verifies that a multipart
// request with no files present passes through to the handler.
func TestFileUpload_EmptyMultipartFormPassesThrough(t *testing.T) {
	router := buildFileUploadRouter(DefaultFileUploadConfig())

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	// Add a non-file field only.
	require.NoError(t, writer.WriteField("description", "hello"))
	require.NoError(t, writer.Close())

	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"multipart form without files must pass through")
}

// ==================== validateFilename unit tests ====================

// TestValidateFilename_TableDriven exercises the filename validator directly.
func TestValidateFilename_TableDriven(t *testing.T) {
	m := NewFileUploadMiddleware()

	tests := []struct {
		filename string
		wantErr  bool
	}{
		{"document.pdf", false},
		{"my-file.txt", false},
		{"report_2024.docx", false},
		{"", true},              // empty
		{"../passwd", true},     // path traversal
		{".htaccess", true},     // hidden file
		{"/etc/passwd", true},   // absolute path
		{"file\x00name", true},  // null byte
		{"has/slash.txt", true}, // slash
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			err := m.validateFilename(tt.filename)
			if tt.wantErr {
				assert.Error(t, err, "expected error for filename %q", tt.filename)
			} else {
				assert.NoError(t, err, "expected no error for filename %q", tt.filename)
			}
		})
	}
}

// ==================== SanitizeFilename ====================

// TestSanitizeFilename verifies that SanitizeFilename produces safe filenames.
func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"document.pdf", "document.pdf"},
		{"../etc/passwd", "passwd"},             // path traversal stripped to base
		{"/absolute/path/file.txt", "file.txt"}, // absolute path stripped
		{"file/with/slash.pdf", "slash.pdf"},
		{"file\\windows.pdf", "file_windows.pdf"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := SanitizeFilename(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// ==================== mimeTypesMatch ====================

// TestMimeTypesMatch_TableDriven exercises the MIME matching helper.
func TestMimeTypesMatch_TableDriven(t *testing.T) {
	tests := []struct {
		type1 string
		type2 string
		match bool
	}{
		{"image/png", "image/png", true},
		{"image/png", "image/jpeg", false},
		{"application/octet-stream", "image/png", true}, // generic binary always matches
		{"image/png", "application/octet-stream", true},
		{"text/plain", "text/csv", true}, // text/plain is a generic text type
		{"text/csv", "text/plain", true},
		{"application/pdf", "application/pdf", true},
		{"application/pdf ", " application/pdf", true},  // whitespace trimmed
		{"image/png; charset=utf-8", "image/png", true}, // charset stripped
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s vs %s", tt.type1, tt.type2), func(t *testing.T) {
			result := mimeTypesMatch(tt.type1, tt.type2)
			assert.Equal(t, tt.match, result)
		})
	}
}

// ==================== DefaultFileUploadConfig ====================

// TestDefaultFileUploadConfig_Values verifies sensible defaults are present.
func TestDefaultFileUploadConfig_Values(t *testing.T) {
	cfg := DefaultFileUploadConfig()

	assert.Equal(t, int64(10*1024*1024), cfg.MaxFileSize, "default MaxFileSize should be 10 MiB")
	assert.Equal(t, int64(50*1024*1024), cfg.MaxTotalSize, "default MaxTotalSize should be 50 MiB")
	assert.NotEmpty(t, cfg.AllowedMimeTypes)
	assert.NotEmpty(t, cfg.AllowedExtensions)
	assert.NotEmpty(t, cfg.BlockedExtensions)
	assert.True(t, cfg.RequireMimeValidation)
	assert.Contains(t, cfg.BlockedExtensions, ".exe")
	assert.Contains(t, cfg.BlockedExtensions, ".php")
	assert.Contains(t, cfg.AllowedExtensions, ".pdf")
}

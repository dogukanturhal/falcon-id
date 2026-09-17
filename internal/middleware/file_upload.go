// SPDX-License-Identifier: AGPL-3.0-or-later

// Package middleware provides HTTP middleware for the IAM service.
package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// FileUploadConfig holds file upload validation middleware configuration
type FileUploadConfig struct {
	// MaxFileSize is the maximum allowed file size in bytes (default: 10MB)
	MaxFileSize int64
	// MaxTotalSize is the maximum allowed total size for multipart uploads (default: 50MB)
	MaxTotalSize int64
	// AllowedMimeTypes is the list of allowed MIME types
	AllowedMimeTypes []string
	// AllowedExtensions is the list of allowed file extensions (with dot)
	AllowedExtensions []string
	// BlockedExtensions is the list of blocked file extensions (with dot)
	BlockedExtensions []string
	// RequireMimeValidation requires content-type to match file magic bytes
	RequireMimeValidation bool
	// ScanForMalware enables malware scanning (requires external service)
	ScanForMalware bool
	// MaxFilenameLength is the maximum allowed filename length
	MaxFilenameLength int
}

// DefaultFileUploadConfig returns secure default file upload configuration
func DefaultFileUploadConfig() FileUploadConfig {
	return FileUploadConfig{
		MaxFileSize:  10 * 1024 * 1024, // 10MB
		MaxTotalSize: 50 * 1024 * 1024, // 50MB
		AllowedMimeTypes: []string{
			// Documents
			"application/pdf",
			"application/msword",
			"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			"application/vnd.ms-excel",
			"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
			"application/vnd.ms-powerpoint",
			"application/vnd.openxmlformats-officedocument.presentationml.presentation",
			"text/plain",
			"text/csv",
			// Images
			"image/jpeg",
			"image/png",
			"image/gif",
			"image/webp",
			"image/svg+xml",
			// Archives (be careful with these)
			"application/zip",
			"application/x-zip-compressed",
		},
		AllowedExtensions: []string{
			// Documents
			".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv",
			// Images
			".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
			// Archives
			".zip",
		},
		BlockedExtensions: []string{
			// Executable files
			".exe", ".dll", ".so", ".dylib",
			".bat", ".cmd", ".com", ".msi",
			".sh", ".bash", ".zsh",
			".ps1", ".psm1", ".psd1",
			// Script files
			".js", ".jsx", ".ts", ".tsx",
			".php", ".phtml", ".php3", ".php4", ".php5",
			".py", ".pyc", ".pyo",
			".rb", ".erb",
			".pl", ".pm", ".cgi",
			".asp", ".aspx",
			".jsp", ".jspx",
			// HTML/Templates (can contain XSS)
			".html", ".htm", ".xhtml",
			".hta", ".htaccess",
			".shtml", ".shtm",
			// Server config
			".htaccess", ".htpasswd",
			".config", ".ini",
			// Dangerous archives
			".jar", ".war", ".ear",
			// Other dangerous
			".scr", ".pif", ".vbs", ".vbe",
			".wsf", ".wsh", ".reg",
		},
		RequireMimeValidation: true,
		ScanForMalware:        false, // Enable if malware scanner is available
		MaxFilenameLength:     255,
	}
}

// FileUploadMiddleware validates file uploads for security
type FileUploadMiddleware struct {
	config FileUploadConfig
}

// NewFileUploadMiddleware creates a new file upload middleware with default config
func NewFileUploadMiddleware() *FileUploadMiddleware {
	return &FileUploadMiddleware{
		config: DefaultFileUploadConfig(),
	}
}

// NewFileUploadMiddlewareWithConfig creates a middleware with custom configuration
func NewFileUploadMiddlewareWithConfig(config FileUploadConfig) *FileUploadMiddleware {
	return &FileUploadMiddleware{
		config: config,
	}
}

// ValidateFileUpload returns a middleware that validates file uploads
// SECURITY: This middleware prevents malicious file uploads and path traversal attacks
func (m *FileUploadMiddleware) ValidateFileUpload() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !strings.HasPrefix(c.ContentType(), "multipart/form-data") {
			c.Next()
			return
		}

		if ok := m.parseMultipartForm(c); !ok {
			return
		}

		if c.Request.MultipartForm == nil || c.Request.MultipartForm.File == nil {
			c.Next()
			return
		}

		if ok := m.validateAllFiles(c); !ok {
			return
		}

		c.Next()
	}
}

// parseMultipartForm limits the body size and parses the multipart form.
// Returns false and aborts the request on error.
func (m *FileUploadMiddleware) parseMultipartForm(c *gin.Context) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, m.config.MaxTotalSize)
	if err := c.Request.ParseMultipartForm(m.config.MaxTotalSize); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":   "file_too_large",
				"message": "Total upload size exceeds the maximum allowed",
			})
			return false
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_multipart",
			"message": "Failed to parse multipart form",
		})
		return false
	}
	return true
}

// validateAllFiles iterates over all uploaded files and validates each one.
// Returns false and aborts the request on the first validation failure.
func (m *FileUploadMiddleware) validateAllFiles(c *gin.Context) bool {
	for fieldName, files := range c.Request.MultipartForm.File {
		for _, fileHeader := range files {
			if err := m.validateFile(fileHeader); err != nil {
				logger.Log.Warn("File upload validation failed",
					zap.String("field", fieldName),
					zap.String("filename", fileHeader.Filename),
					zap.String("error", err.Error()),
				)
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error":   "file_validation_failed",
					"message": err.Error(),
					"field":   fieldName,
				})
				return false
			}
		}
	}
	return true
}

// validateFile validates a single file upload
func (m *FileUploadMiddleware) validateFile(fileHeader *multipart.FileHeader) error {
	filename := fileHeader.Filename

	// SECURITY: Validate filename length
	if len(filename) > m.config.MaxFilenameLength {
		return &FileValidationError{
			Code:    "filename_too_long",
			Message: "Filename exceeds maximum length",
		}
	}

	// SECURITY: Sanitize and validate filename (prevent path traversal)
	if err := m.validateFilename(filename); err != nil {
		return fmt.Errorf("validateFile: %w", err)
	}

	// SECURITY: Validate file size
	if fileHeader.Size > m.config.MaxFileSize {
		return &FileValidationError{
			Code:    "file_too_large",
			Message: "File size exceeds maximum allowed",
		}
	}

	// SECURITY: Validate file extension
	ext := strings.ToLower(filepath.Ext(filename))
	if err := m.validateExtension(ext); err != nil {
		return fmt.Errorf("validateFile: %w", err)
	}

	// SECURITY: Validate MIME type
	if err := m.validateMimeType(fileHeader); err != nil {
		return fmt.Errorf("validateFile: %w", err)
	}

	return nil
}

// validateFilename validates the filename for path traversal and other attacks
func (m *FileUploadMiddleware) validateFilename(filename string) error {
	// SECURITY: Reject empty filename
	if filename == "" {
		return &FileValidationError{
			Code:    "empty_filename",
			Message: "Filename cannot be empty",
		}
	}

	// SECURITY: Reject path traversal attempts
	if strings.Contains(filename, "..") {
		return &FileValidationError{
			Code:    "path_traversal",
			Message: "Filename contains invalid path sequence",
		}
	}

	// SECURITY: Reject absolute paths
	if filepath.IsAbs(filename) {
		return &FileValidationError{
			Code:    "absolute_path",
			Message: "Filename cannot be an absolute path",
		}
	}

	// SECURITY: Reject filenames with path separators
	if strings.ContainsAny(filename, "/\\") {
		return &FileValidationError{
			Code:    "path_separator",
			Message: "Filename cannot contain path separators",
		}
	}

	// SECURITY: Reject hidden files (starting with dot)
	if strings.HasPrefix(filename, ".") {
		return &FileValidationError{
			Code:    "hidden_file",
			Message: "Hidden files are not allowed",
		}
	}

	// SECURITY: Reject null bytes (can be used in attacks)
	if strings.Contains(filename, "\x00") {
		return &FileValidationError{
			Code:    "null_byte",
			Message: "Filename contains invalid characters",
		}
	}

	// SECURITY: Reject control characters
	for _, r := range filename {
		if r < 32 {
			return &FileValidationError{
				Code:    "control_character",
				Message: "Filename contains control characters",
			}
		}
	}

	return nil
}

// validateExtension validates the file extension
func (m *FileUploadMiddleware) validateExtension(ext string) error {
	// SECURITY: Check blocked extensions first (takes precedence)
	for _, blocked := range m.config.BlockedExtensions {
		if strings.EqualFold(ext, blocked) {
			return &FileValidationError{
				Code:    "blocked_extension",
				Message: "This file type is not allowed",
			}
		}
	}

	// SECURITY: Check against allowed extensions
	if len(m.config.AllowedExtensions) > 0 {
		allowed := false
		for _, allowedExt := range m.config.AllowedExtensions {
			if strings.EqualFold(ext, allowedExt) {
				allowed = true
				break
			}
		}
		if !allowed {
			return &FileValidationError{
				Code:    "invalid_extension",
				Message: "This file type is not allowed",
			}
		}
	}

	return nil
}

// validateMimeType validates the MIME type of the file
func (m *FileUploadMiddleware) validateMimeType(fileHeader *multipart.FileHeader) error {
	declaredType := fileHeader.Header.Get("Content-Type")

	buffer, err := readFileMagicBytes(fileHeader)
	if err != nil {
		return err
	}

	detectedType := http.DetectContentType(buffer)

	if m.config.RequireMimeValidation && declaredType != "" && !mimeTypesMatch(declaredType, detectedType) {
		logger.Log.Warn("MIME type mismatch",
			zap.String("declared", declaredType),
			zap.String("detected", detectedType),
			zap.String("filename", fileHeader.Filename),
		)
	}

	if err := m.checkAllowedMimeType(declaredType, detectedType); err != nil {
		return err
	}

	if err := m.checkForPolyglot(buffer, fileHeader.Filename); err != nil {
		return fmt.Errorf("validateMimeType: %w", err)
	}

	return nil
}

// readFileMagicBytes opens the file and reads the first 512 bytes used for MIME detection.
func readFileMagicBytes(fileHeader *multipart.FileHeader) ([]byte, error) {
	file, err := fileHeader.Open()
	if err != nil {
		return nil, &FileValidationError{Code: "file_open_error", Message: "Failed to open file for validation"}
	}
	defer file.Close() //nolint:errcheck

	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, &FileValidationError{Code: "file_read_error", Message: "Failed to read file for validation"}
	}
	buffer = buffer[:n]

	if seeker, ok := file.(io.Seeker); ok {
		_, _ = seeker.Seek(0, io.SeekStart)
	}
	return buffer, nil
}

// checkAllowedMimeType returns an error when neither the detected nor declared type is in the allowed list.
func (m *FileUploadMiddleware) checkAllowedMimeType(declaredType, detectedType string) error {
	if len(m.config.AllowedMimeTypes) == 0 {
		return nil
	}
	for _, allowedType := range m.config.AllowedMimeTypes {
		if mimeTypesMatch(detectedType, allowedType) || mimeTypesMatch(declaredType, allowedType) {
			return nil
		}
	}
	return &FileValidationError{Code: "invalid_mime_type", Message: "This file type is not allowed"}
}

// checkForPolyglot checks for polyglot file attacks
func (m *FileUploadMiddleware) checkForPolyglot(content []byte, filename string) error {
	ext := strings.ToLower(filepath.Ext(filename))

	// Check for PHP in images (common attack vector)
	if isImageExtension(ext) {
		if bytes.Contains(content, []byte("<?php")) ||
			bytes.Contains(content, []byte("<?=")) ||
			bytes.Contains(content, []byte("<script")) {
			return &FileValidationError{
				Code:    "polyglot_detected",
				Message: "File appears to contain embedded code",
			}
		}
	}

	// Check for HTML/JS in non-HTML files
	if ext != ".html" && ext != ".htm" {
		if bytes.Contains(content, []byte("<script")) &&
			bytes.Contains(content, []byte("</script>")) {
			return &FileValidationError{
				Code:    "script_detected",
				Message: "File contains embedded scripts",
			}
		}
	}

	return nil
}

// FileValidationError represents a file validation error
type FileValidationError struct {
	Code    string
	Message string
}

func (e *FileValidationError) Error() string {
	return e.Message
}

// mimeTypesMatch checks if two MIME types match (handling subtypes)
func mimeTypesMatch(type1, type2 string) bool {
	// Normalize types
	type1 = strings.ToLower(strings.TrimSpace(type1))
	type2 = strings.ToLower(strings.TrimSpace(type2))

	// Extract base type (before semicolon for charset etc)
	if idx := strings.Index(type1, ";"); idx != -1 {
		type1 = strings.TrimSpace(type1[:idx])
	}
	if idx := strings.Index(type2, ";"); idx != -1 {
		type2 = strings.TrimSpace(type2[:idx])
	}

	// Exact match
	if type1 == type2 {
		return true
	}

	// Handle application/octet-stream (generic binary)
	if type1 == "application/octet-stream" || type2 == "application/octet-stream" {
		return true
	}

	// Handle text/plain as generic text
	if (type1 == "text/plain" && strings.HasPrefix(type2, "text/")) ||
		(type2 == "text/plain" && strings.HasPrefix(type1, "text/")) {
		return true
	}

	return false
}

// isImageExtension checks if the extension is an image type
func isImageExtension(ext string) bool {
	imageExts := []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico", ".svg"}
	for _, imgExt := range imageExts {
		if ext == imgExt {
			return true
		}
	}
	return false
}

// SanitizeFilename returns a sanitized version of the filename
// This can be used by handlers that need to save files
func SanitizeFilename(filename string) string {
	// Get base name only
	filename = filepath.Base(filename)

	// Remove any path separators that might have snuck through
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")

	// Remove null bytes
	filename = strings.ReplaceAll(filename, "\x00", "")

	// Remove control characters
	result := make([]rune, 0, len(filename))
	for _, r := range filename {
		if r >= 32 {
			result = append(result, r)
		}
	}
	filename = string(result)

	// Truncate if too long
	if len(filename) > 255 {
		ext := filepath.Ext(filename)
		name := strings.TrimSuffix(filename, ext)
		maxNameLen := 255 - len(ext)
		if len(name) > maxNameLen {
			name = name[:maxNameLen]
		}
		filename = name + ext
	}

	return filename
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/services"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// auditContextKey is a typed key for context values to prevent collisions across packages.
type auditContextKey string

const (
	auditKeyActorID     auditContextKey = "actor_id"
	auditKeyActorEmail  auditContextKey = "actor_email"
	auditKeyTenantID    auditContextKey = "tenant_id"
	auditKeyIPAddress   auditContextKey = "ip_address"
	auditKeyCountryCode auditContextKey = "country_code"
	auditKeyUserAgent   auditContextKey = "user_agent"
	auditKeyRequestID   auditContextKey = "request_id"

	httpMethodPOST   = "POST"
	httpMethodDELETE = "DELETE"
	httpMethodPUT    = "PUT"

	auditResourceUser             = "user"
	auditResourceRole             = "role"
	auditResourceIdentityProvider = "identity_provider"
	auditResourceSecurity         = "security"
)

// AuditMiddleware logs admin actions for compliance and security
type AuditMiddleware struct {
	auditService *services.AdminAuditService
}

// NewAuditMiddleware creates a new audit middleware
func NewAuditMiddleware(auditService *services.AdminAuditService) *AuditMiddleware {
	return &AuditMiddleware{
		auditService: auditService,
	}
}

// responseWriter is a custom response writer that captures the status code and response body
type responseWriter struct {
	gin.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func newResponseWriter(w gin.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// AuditAdmin middleware that logs all admin actions
func (m *AuditMiddleware) AuditAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api/admin") {
			c.Next()
			return
		}

		method := c.Request.Method
		if method == "GET" && !isSensitiveReadEndpoint(c.Request.URL.Path) {
			c.Next()
			return
		}

		startTime := time.Now()

		currentUser := GetCurrentUser(c)
		if currentUser == nil {
			c.Next()
			return
		}

		requestBody := captureRequestBody(c, method)

		rw := newResponseWriter(c.Writer)
		c.Writer = rw
		c.Next()

		m.emitAuditEvent(c, currentUser, method, startTime, rw, requestBody)
	}
}

// captureRequestBody reads and restores the request body, returning its parsed JSON.
func captureRequestBody(c *gin.Context, method string) map[string]interface{} {
	if method == "GET" || method == httpMethodDELETE {
		return nil
	}
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil
	}
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	var requestBody map[string]interface{}
	_ = json.Unmarshal(bodyBytes, &requestBody)
	return requestBody
}

// emitAuditEvent builds and fires the admin audit event asynchronously.
func (m *AuditMiddleware) emitAuditEvent(
	c *gin.Context,
	currentUser *models.CurrentUser,
	method string,
	startTime time.Time,
	rw *responseWriter,
	_ map[string]interface{},
) {
	duration := time.Since(startTime).Milliseconds()
	success := rw.statusCode >= 200 && rw.statusCode < 400
	action, resource, resourceID := determineAction(c)

	// Audit log stores the real public IP of the client making the
	// privileged / PII-impacting call — APISIX-stamped X-Real-IP from
	// CF-Connecting-IP, edge-vouched by Cloudflare. The TCP peer (APISIX
	// pod IP) has no audit value because it's identical across every
	// inbound request.
	ipAddress := ClientIP(c.Request)
	countryCode := ClientCountry(c.Request)
	userAgent := c.GetHeader("User-Agent")
	requestID := getRequestID(c)
	tenantID := currentUser.TenantID
	actorID := currentUser.ID
	actorEmail := currentUser.Email

	responseBody := parseSuccessResponseBody(rw, success, method)
	errorMsg := parseErrorMessage(rw, success)

	ctx := context.WithoutCancel(c.Request.Context())
	ctx = context.WithValue(ctx, auditKeyActorID, actorID)
	ctx = context.WithValue(ctx, auditKeyActorEmail, actorEmail)
	ctx = context.WithValue(ctx, auditKeyTenantID, tenantID)
	ctx = context.WithValue(ctx, auditKeyIPAddress, ipAddress)
	ctx = context.WithValue(ctx, auditKeyCountryCode, countryCode)
	ctx = context.WithValue(ctx, auditKeyUserAgent, userAgent)
	ctx = context.WithValue(ctx, auditKeyRequestID, requestID)

	details := map[string]interface{}{
		"method":      method,
		"path":        c.Request.URL.Path,
		"status_code": rw.statusCode,
	}

	event := &services.AdminAuditEvent{
		TenantID:    tenantID,
		ActorID:     actorID,
		ActorEmail:  actorEmail,
		Action:      action,
		Resource:    resource,
		ResourceID:  resourceID,
		OldValue:    nil,
		NewValue:    responseBody,
		Details:     details,
		IPAddress:   ipAddress,
		CountryCode: countryCode,
		UserAgent:   userAgent,
		RequestID:   requestID,
		Success:     success,
		ErrorMsg:    errorMsg,
		Duration:    duration,
		Timestamp:   startTime,
	}

	go func() {
		if err := m.auditService.LogEvent(ctx, event); err != nil {
			logger.Error("Failed to log admin audit event",
				zap.String("action", action),
				zap.Error(err),
			)
		}
	}()
}

// parseSuccessResponseBody returns the parsed JSON body for successful POST/PUT responses.
func parseSuccessResponseBody(rw *responseWriter, success bool, method string) map[string]interface{} {
	if !success || (method != httpMethodPOST && method != httpMethodPUT) {
		return nil
	}
	var body map[string]interface{}
	_ = json.Unmarshal(rw.body.Bytes(), &body)
	return body
}

// parseErrorMessage returns a pointer to the error message string from a failed response body.
func parseErrorMessage(rw *responseWriter, success bool) *string {
	if success {
		return nil
	}
	var errResponse map[string]interface{}
	if err := json.Unmarshal(rw.body.Bytes(), &errResponse); err != nil {
		return nil
	}
	if errMsg, ok := errResponse["error"].(string); ok {
		return &errMsg
	}
	return nil
}

// determineAction extracts the action and resource from the request
func determineAction(c *gin.Context) (action string, resource string, resourceID *uuid.UUID) {
	method := c.Request.Method
	path := c.Request.URL.Path

	// Parse resource ID from path if present
	if id := c.Param("id"); id != "" {
		if parsed, err := uuid.Parse(id); err == nil {
			resourceID = &parsed
		}
	}

	if strings.Contains(path, "/users") {
		if a, r := determineUserAction(path, method); a != "" {
			return a, r, resourceID
		}
	}
	if strings.Contains(path, "/roles") {
		if a, r := determineRoleAction(path, method); a != "" {
			return a, r, resourceID
		}
	}
	if strings.Contains(path, "/identity-providers") {
		if a, r := determineIDPAction(path, method); a != "" {
			return a, r, resourceID
		}
	}
	if strings.Contains(path, "/security/") {
		if a, r := determineSecurityAction(path, method); a != "" {
			return a, r, resourceID
		}
	}
	if strings.Contains(path, "/sessions") && method == httpMethodDELETE {
		return "session.revoke", "session", resourceID
	}
	if strings.Contains(path, "/impersonate") {
		return "admin.impersonate", "impersonation", resourceID
	}
	return "admin.unknown_action", "unknown", resourceID
}

// determineUserAction returns the action and resource for user-related paths.
func determineUserAction(path, method string) (string, string) {
	switch {
	case strings.Contains(path, "/password"):
		return "user.password_reset", auditResourceUser
	case strings.Contains(path, "/unlock"):
		return "user.unlock", auditResourceUser
	case strings.Contains(path, "/lock"):
		return "user.lock", auditResourceUser
	case strings.Contains(path, "/roles"):
		return "user.roles_update", auditResourceUser
	case strings.Contains(path, "/mfa"):
		return "user.mfa_update", auditResourceUser
	case method == httpMethodPOST:
		return "user.create", auditResourceUser
	case method == httpMethodPUT:
		return "user.update", auditResourceUser
	case method == httpMethodDELETE:
		return "user.delete", auditResourceUser
	}
	return "", ""
}

// determineRoleAction returns the action and resource for role-related paths.
func determineRoleAction(path, method string) (string, string) {
	switch {
	case strings.Contains(path, "/permissions"):
		return "role.permissions_update", auditResourceRole
	case method == httpMethodPOST:
		return "role.create", auditResourceRole
	case method == httpMethodPUT:
		return "role.update", auditResourceRole
	case method == httpMethodDELETE:
		return "role.delete", auditResourceRole
	}
	return "", ""
}

// determineIDPAction returns the action and resource for identity provider paths.
func determineIDPAction(path, method string) (string, string) {
	switch {
	case strings.Contains(path, "/sync"):
		return "identity_provider.sync", auditResourceIdentityProvider
	case method == httpMethodPOST:
		return "identity_provider.create", auditResourceIdentityProvider
	case method == httpMethodPUT:
		return "identity_provider.update", auditResourceIdentityProvider
	case method == httpMethodDELETE:
		return "identity_provider.delete", auditResourceIdentityProvider
	}
	return "", ""
}

// determineSecurityAction returns the action and resource for security paths.
func determineSecurityAction(path, method string) (string, string) {
	switch {
	case strings.Contains(path, "/password-policy"):
		return "security.password_policy_update", auditResourceSecurity
	case strings.Contains(path, "/rate-limits") && method == httpMethodPOST:
		return "security.rate_limit_create", auditResourceSecurity
	case strings.Contains(path, "/rate-limits") && method == httpMethodPUT:
		return "security.rate_limit_update", auditResourceSecurity
	case strings.Contains(path, "/rate-limits") && method == httpMethodDELETE:
		return "security.rate_limit_delete", auditResourceSecurity
	case strings.Contains(path, "/ip-rules") && method == httpMethodPOST:
		return "security.ip_rule_create", auditResourceSecurity
	case strings.Contains(path, "/ip-rules") && method == httpMethodPUT:
		return "security.ip_rule_update", auditResourceSecurity
	case strings.Contains(path, "/ip-rules") && method == httpMethodDELETE:
		return "security.ip_rule_delete", auditResourceSecurity
	}
	return "", ""
}

// isSensitiveReadEndpoint determines if a GET request should be logged
func isSensitiveReadEndpoint(path string) bool {
	sensitiveEndpoints := []string{
		"/audit-logs",
		"/sessions",
		"/api-keys",
		"/oauth-clients",
		"/service-accounts",
		"/security/",
		"/impersonation",
	}

	for _, endpoint := range sensitiveEndpoints {
		if strings.Contains(path, endpoint) {
			return true
		}
	}
	return false
}

// getRequestID extracts or generates a request ID
func getRequestID(c *gin.Context) string {
	// Try to get existing request ID from header
	if reqID := c.GetHeader("X-Request-ID"); reqID != "" {
		return reqID
	}
	if reqID := c.GetHeader("X-Correlation-ID"); reqID != "" {
		return reqID
	}

	// Try to get from context (set by correlation ID middleware)
	if reqID, exists := c.Get("request_id"); exists {
		if id, ok := reqID.(string); ok {
			return id
		}
	}

	// Generate new UUID
	return uuid.New().String()
}

// Note: GetCurrentUser is defined in auth.go - use that implementation

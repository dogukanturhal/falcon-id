// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const hcmSourceIAM = "iam"

// sanitizeString strips null bytes, HTML tags, trims whitespace, and truncates
// a string to maxLen bytes. It should be applied to all user-supplied payload
// fields before they are persisted or forwarded to other services.
func sanitizeHCMString(s string, maxLen int) string {
	// Remove null bytes — these can cause issues in SQL and downstream systems.
	s = strings.ReplaceAll(s, "\x00", "")
	// Trim leading/trailing whitespace.
	s = strings.TrimSpace(s)
	// Strip HTML/XML tags with a simple angle-bracket regex.
	htmlTag := regexp.MustCompile(`<[^>]*>`)
	s = htmlTag.ReplaceAllString(s, "")
	s = strings.TrimSpace(s)
	// Truncate to the maximum allowed byte length.
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

// validateEmail returns true when email matches a basic RFC-5322-subset pattern.
// It is intentionally conservative — if in doubt it returns false.
func validateEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// RealmResolver resolves a tenant ID to its corresponding Realm. It is
// satisfied by *RealmService (which already implements GetTenantRealm).
type RealmResolver interface {
	GetTenantRealm(ctx context.Context, tenantID uuid.UUID) (*models.Realm, error)
}

// hcmUserRepo is the subset of the user repository that the HCM consumer needs.
// Keeping this narrow avoids coupling to the full userServiceUserRepo interface.
type hcmUserRepo interface {
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error)
}

// ----------------------------------------------------------------------------
// Event payload types
// ----------------------------------------------------------------------------

// HCMEmployeeHiredPayload is the payload of a example.hr.employee.hired event.
type HCMEmployeeHiredPayload struct {
	EmployeeID     string `json:"employee_id"`
	EmployeeNumber string `json:"employee_number"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	Email          string `json:"email"`
	Phone          string `json:"phone"`
	IamUserID      string `json:"iam_user_id"` // non-empty means already linked — skip
	Source         string `json:"source"`      // "iam" means created by this service — skip
}

// HCMEmployeeUpdatedPayload is the payload of a example.hr.employee.updated event.
type HCMEmployeeUpdatedPayload struct {
	EmployeeID     string `json:"employee_id"`
	EmployeeNumber string `json:"employee_number"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
	Email          string `json:"email"`
	Phone          string `json:"phone"`
	IamUserID      string `json:"iam_user_id"`
	Source         string `json:"source"`
}

// HCMEmployeeTerminatedPayload is the payload of a example.hr.employee.terminated event.
type HCMEmployeeTerminatedPayload struct {
	EmployeeID     string `json:"employee_id"`
	EmployeeNumber string `json:"employee_number"`
	Email          string `json:"email"`
	IamUserID      string `json:"iam_user_id"`
	Source         string `json:"source"`
}

// IntegrationBusMessage is the envelope returned by the integration bus consume endpoint.
type IntegrationBusMessage struct {
	ID        string          `json:"id"`
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
	TenantID  string          `json:"tenant_id"`
	CreatedAt time.Time       `json:"created_at"`
}

// ----------------------------------------------------------------------------
// HCMEmployeeConsumer
// ----------------------------------------------------------------------------

const (
	hcmSubscriberCode = "falcon-id-hcm-sync"
	hcmPollInterval   = 15 * time.Second
	hcmConsumeLimit   = 20
	hcmHTTPTimeout    = 10 * time.Second
)

var hcmEventTypes = []string{
	"example.hr.employee.hired",
	"example.hr.employee.updated",
	"example.hr.employee.terminated",
}

// HCMEmployeeConsumer is a background consumer that polls the integration bus
// for HCM employee lifecycle events and creates / updates / disables IAM users
// accordingly. It also provisions the user in Active Directory when an
// LDAPService is wired (i.e., ldapService != nil).
type HCMEmployeeConsumer struct {
	userService   *UserService
	ldapService   *LDAPService // nil when LDAP is not configured
	userRepo      hcmUserRepo
	httpClient    *http.Client
	busBaseURL    string
	realmResolver RealmResolver
	logger        *zap.Logger
}

// NewHCMEmployeeConsumer creates a new HCMEmployeeConsumer. ldapService may be
// nil — when it is nil, AD provisioning is silently skipped.
//
// DEPRECATE-3 (2026-05-24): constructor takes a `*http.Client` whose
// Transport wraps `serviceauth.TokenClient.RoundTripper`. Replaces the
// previous `internalAPIKey string` parameter — outbound calls to
// integration-bus carry OAuth2 client_credentials Bearer JWT instead of
// the legacy `X-Internal-Key` shared-secret header.
//
// integration-bus migrated to JWKS-required ServiceAuth on
// `/api/v1/integration/{events,internal/*}` (falcon-id !232), so the
// previous no-auth / X-Internal-Key path is no longer accepted there.
// Caller owns the timeout; pass `&http.Client{Timeout:
// hcmHTTPTimeout, Transport: tokenClient.RoundTripper(nil)}`.
//
// Memory: internal engineering notes.
//
// Note: this constructor was not wired into any cmd/ codepath at the
// time of this MR (the consumer is reachable code but never started).
// The signature change ensures the bus call path is correct the moment
// somebody wires it.
func NewHCMEmployeeConsumer(
	userService *UserService,
	ldapService *LDAPService,
	userRepo hcmUserRepo,
	busBaseURL string,
	httpClient *http.Client,
	realmResolver RealmResolver,
	logger *zap.Logger,
) *HCMEmployeeConsumer {
	return &HCMEmployeeConsumer{
		userService:   userService,
		ldapService:   ldapService,
		userRepo:      userRepo,
		busBaseURL:    busBaseURL,
		httpClient:    httpClient,
		realmResolver: realmResolver,
		logger:        logger,
	}
}

// Start registers subscriptions once, then enters an infinite polling loop.
// It blocks until ctx is cancelled; call it in a goroutine.
func (c *HCMEmployeeConsumer) Start(ctx context.Context) {
	c.logger.Info("HCM employee consumer starting",
		zap.String("bus_url", c.busBaseURL),
		zap.Duration("poll_interval", hcmPollInterval),
	)

	// Best-effort subscription registration at startup.
	c.registerSubscriptions(ctx)

	ticker := time.NewTicker(hcmPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("HCM employee consumer stopped")
			return
		case <-ticker.C:
			if err := c.pollAndProcess(ctx); err != nil {
				c.logger.Warn("HCM employee consumer poll error", zap.Error(err))
			}
		}
	}
}

// registerSubscriptions registers the consumer's event type subscriptions with
// the integration bus. Errors are logged and never returned — a failed
// registration is retried on the next process start.
func (c *HCMEmployeeConsumer) registerSubscriptions(ctx context.Context) {
	for _, et := range hcmEventTypes {
		body := map[string]string{
			"subscriber_code": hcmSubscriberCode,
			"event_type":      et,
		}

		data, err := json.Marshal(body)
		if err != nil {
			c.logger.Warn("HCM: failed to marshal subscription request",
				zap.String("event_type", et),
				zap.Error(err),
			)
			continue
		}

		// Use the internal cross-tenant subscription endpoint — no X-Tenant-ID required.
		url := c.busBaseURL + "/api/v1/integration/internal/subscriptions"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			c.logger.Warn("HCM: failed to build subscription request",
				zap.String("event_type", et),
				zap.Error(err),
			)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		// Authorization Bearer is attached by the TokenClient.RoundTripper
		// transport on c.httpClient (DEPRECATE-3). No X-Internal-Key.

		resp, err := c.httpClient.Do(req)
		if err != nil {
			c.logger.Warn("HCM: subscription request failed",
				zap.String("event_type", et),
				zap.Error(err),
			)
			continue
		}
		resp.Body.Close() //nolint:errcheck,gosec

		c.logger.Info("HCM: subscription registered",
			zap.String("event_type", et),
			zap.Int("status", resp.StatusCode),
		)
	}
}

// pollAndProcess fetches up to hcmConsumeLimit messages for each registered
// event type and processes them.
func (c *HCMEmployeeConsumer) pollAndProcess(ctx context.Context) error { //nolint:unparam // error return is always nil currently but kept for future use
	for _, et := range hcmEventTypes {
		messages, err := c.consumeEvents(ctx, et)
		if err != nil {
			c.logger.Warn("HCM: consume failed",
				zap.String("event_type", et),
				zap.Error(err),
			)
			continue
		}

		for _, msg := range messages {
			c.processMessage(ctx, msg)
		}
	}

	return nil
}

// consumeEvents polls the integration bus for messages of eventType.
// Uses the internal cross-tenant consume endpoint — no X-Tenant-ID header required.
func (c *HCMEmployeeConsumer) consumeEvents(ctx context.Context, eventType string) ([]IntegrationBusMessage, error) {
	url := fmt.Sprintf(
		"%s/api/v1/integration/internal/events/consume?subscriber=%s&event_type=%s&limit=%d",
		c.busBaseURL, hcmSubscriberCode, eventType, hcmConsumeLimit,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("consumeEvents: build request: %w", err)
	}
	// Authenticate with the internal API key when available.
	// Authorization Bearer is attached by the TokenClient.RoundTripper
	// transport on c.httpClient (DEPRECATE-3).

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("consumeEvents: http: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("consumeEvents: unexpected status %d for %s", resp.StatusCode, eventType)
	}

	var messages []IntegrationBusMessage
	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		return nil, fmt.Errorf("consumeEvents: decode: %w", err)
	}

	return messages, nil
}

// processMessage dispatches a single bus message to the appropriate handler.
// All errors are logged; the consumer never panics.
func (c *HCMEmployeeConsumer) processMessage(ctx context.Context, msg IntegrationBusMessage) {
	switch msg.EventType {
	case "example.hr.employee.hired":
		c.handleEmployeeHired(ctx, msg)
	case "example.hr.employee.updated":
		c.handleEmployeeUpdated(ctx, msg)
	case "example.hr.employee.terminated":
		c.handleEmployeeTerminated(ctx, msg)
	default:
		c.logger.Warn("HCM: unknown event type", zap.String("event_type", msg.EventType))
	}
}

// ----------------------------------------------------------------------------
// hired
// ----------------------------------------------------------------------------

func (c *HCMEmployeeConsumer) handleEmployeeHired(ctx context.Context, msg IntegrationBusMessage) {
	var p HCMEmployeeHiredPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		c.logger.Warn("HCM: failed to unmarshal hired payload",
			zap.String("event_id", msg.ID),
			zap.Error(err),
		)
		return
	}

	log := c.logger.With(
		zap.String("event_id", msg.ID),
		zap.String("employee_id", p.EmployeeID),
		zap.String("email", p.Email),
	)

	// Prevent circular sync: skip events we ourselves emitted.
	if p.Source == hcmSourceIAM {
		log.Debug("HCM: hired — skipping event sourced by IAM (circular sync guard)")
		return
	}

	// Skip employees already linked to an IAM user.
	if p.IamUserID != "" {
		log.Debug("HCM: hired — employee already linked to IAM user, skipping",
			zap.String("iam_user_id", p.IamUserID),
		)
		return
	}

	// Sanitize and validate all payload fields before use.
	email := sanitizeHCMString(p.Email, 254)
	firstName := sanitizeHCMString(p.FirstName, 100)
	lastName := sanitizeHCMString(p.LastName, 100)
	phone := sanitizeHCMString(p.Phone, 50)

	if email == "" {
		log.Warn("HCM: hired — payload missing email, cannot create IAM user")
		return
	}
	if !validateEmail(email) {
		log.Warn("HCM: hired — payload email is invalid, cannot create IAM user",
			zap.String("email", email),
		)
		return
	}

	tenantID, err := uuid.Parse(msg.TenantID)
	if err != nil {
		log.Warn("HCM: hired — invalid tenant_id", zap.String("tenant_id", msg.TenantID), zap.Error(err))
		return
	}

	// Idempotency: check whether an IAM user already exists for this email.
	existing, err := c.userRepo.GetByEmail(ctx, tenantID, email)
	if err != nil {
		log.Warn("HCM: hired — failed to check existing user by email", zap.Error(err))
		return
	}
	if existing != nil {
		log.Info("HCM: hired — IAM user already exists for email, skipping creation",
			zap.String("user_id", existing.ID.String()),
		)
		return
	}

	// Generate a unique username.
	// NOTE: resolveRealmID is intentionally omitted here. UserService.Create
	// resolves the realm internally via its realmResolver, so calling it here
	// would be redundant dead code (Finding 8).
	username, err := c.generateUniqueUsername(ctx, tenantID, firstName, lastName)
	if err != nil {
		log.Warn("HCM: hired — failed to generate username", zap.Error(err))
		return
	}

	// Generate a temporary password the employee must change on first login.
	tempPassword, err := generateTemporaryPassword()
	if err != nil {
		log.Warn("HCM: hired — failed to generate temporary password", zap.Error(err))
		return
	}

	req := &models.CreateUserRequest{
		TenantID:  tenantID,
		Username:  username,
		Email:     email,
		Password:  tempPassword,
		FirstName: &firstName,
		LastName:  &lastName,
		Phone:     &phone,
	}

	// UserService.Create sets IsActive=true by default.
	// MustChangePassword is enforced via a subsequent Update call because
	// CreateUserRequest does not carry that field.
	createdResp, err := c.userService.Create(ctx, req, nil)
	if err != nil {
		log.Warn("HCM: hired — failed to create IAM user", zap.Error(err))
		return
	}

	// Set MustChangePassword = true via an Update so the employee is forced to
	// choose their own password on first login.
	mustChangeBool := true
	if _, updateErr := c.userService.Update(ctx, createdResp.ID, &models.UpdateUserRequest{
		MustChangePassword: &mustChangeBool,
	}, nil); updateErr != nil {
		log.Warn("HCM: hired — failed to set MustChangePassword, continuing",
			zap.String("user_id", createdResp.ID.String()),
			zap.Error(updateErr),
		)
	}

	log.Info("HCM: hired — IAM user created",
		zap.String("user_id", createdResp.ID.String()),
		zap.String("username", createdResp.Username),
	)

	// Optionally provision to Active Directory.
	if c.ldapService != nil {
		c.provisionToAD(ctx, log, createdResp.ID, username, email, firstName, lastName, "", "", tempPassword)
	}
}

// ----------------------------------------------------------------------------
// updated
// ----------------------------------------------------------------------------

func (c *HCMEmployeeConsumer) handleEmployeeUpdated(ctx context.Context, msg IntegrationBusMessage) {
	var p HCMEmployeeUpdatedPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		c.logger.Warn("HCM: failed to unmarshal updated payload",
			zap.String("event_id", msg.ID),
			zap.Error(err),
		)
		return
	}

	log := c.logger.With(
		zap.String("event_id", msg.ID),
		zap.String("employee_id", p.EmployeeID),
		zap.String("email", p.Email),
	)

	if p.Source == hcmSourceIAM {
		log.Debug("HCM: updated — skipping event sourced by IAM (circular sync guard)")
		return
	}

	tenantID, err := uuid.Parse(msg.TenantID)
	if err != nil {
		log.Warn("HCM: updated — invalid tenant_id", zap.String("tenant_id", msg.TenantID), zap.Error(err))
		return
	}

	// Sanitize payload fields before use.
	email := sanitizeHCMString(p.Email, 254)
	firstName := sanitizeHCMString(p.FirstName, 100)
	lastName := sanitizeHCMString(p.LastName, 100)
	phone := sanitizeHCMString(p.Phone, 50)

	// Resolve IAM user: prefer explicit iam_user_id, fall back to email lookup.
	user, err := c.resolveUser(ctx, tenantID, p.IamUserID, email)
	if err != nil {
		log.Warn("HCM: updated — failed to resolve IAM user", zap.Error(err))
		return
	}
	if user == nil {
		log.Info("HCM: updated — no IAM user found, skipping update")
		return
	}

	updateReq := &models.UpdateUserRequest{
		FirstName: &firstName,
		LastName:  &lastName,
		Phone:     &phone,
	}

	if _, err := c.userService.Update(ctx, user.ID, updateReq, nil); err != nil {
		log.Warn("HCM: updated — failed to update IAM user",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		return
	}

	log.Info("HCM: updated — IAM user updated",
		zap.String("user_id", user.ID.String()),
	)

	// Optionally update Active Directory.
	if c.ldapService != nil && user.FederationID != nil {
		c.updateInAD(ctx, log, *user.FederationID, firstName, lastName, "", "", phone)
	}
}

// ----------------------------------------------------------------------------
// terminated
// ----------------------------------------------------------------------------

func (c *HCMEmployeeConsumer) handleEmployeeTerminated(ctx context.Context, msg IntegrationBusMessage) {
	var p HCMEmployeeTerminatedPayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		c.logger.Warn("HCM: failed to unmarshal terminated payload",
			zap.String("event_id", msg.ID),
			zap.Error(err),
		)
		return
	}

	log := c.logger.With(
		zap.String("event_id", msg.ID),
		zap.String("employee_id", p.EmployeeID),
		zap.String("email", p.Email),
	)

	if p.Source == hcmSourceIAM {
		log.Debug("HCM: terminated — skipping event sourced by IAM (circular sync guard)")
		return
	}

	tenantID, err := uuid.Parse(msg.TenantID)
	if err != nil {
		log.Warn("HCM: terminated — invalid tenant_id", zap.String("tenant_id", msg.TenantID), zap.Error(err))
		return
	}

	// Sanitize lookup fields before use.
	email := sanitizeHCMString(p.Email, 254)

	user, err := c.resolveUser(ctx, tenantID, p.IamUserID, email)
	if err != nil {
		log.Warn("HCM: terminated — failed to resolve IAM user", zap.Error(err))
		return
	}
	if user == nil {
		log.Info("HCM: terminated — no IAM user found, nothing to disable")
		return
	}

	isActive := false
	if _, err := c.userService.Update(ctx, user.ID, &models.UpdateUserRequest{
		IsActive: &isActive,
	}, nil); err != nil {
		log.Warn("HCM: terminated — failed to disable IAM user",
			zap.String("user_id", user.ID.String()),
			zap.Error(err),
		)
		return
	}

	log.Info("HCM: terminated — IAM user disabled",
		zap.String("user_id", user.ID.String()),
	)

	// Optionally disable in Active Directory.
	if c.ldapService != nil && user.FederationID != nil {
		if adErr := c.ldapService.DisableEmployee(ctx, *user.FederationID); adErr != nil {
			log.Warn("HCM: terminated — failed to disable AD user",
				zap.String("user_dn", *user.FederationID),
				zap.Error(adErr),
			)
		} else {
			log.Info("HCM: terminated — AD user disabled",
				zap.String("user_dn", *user.FederationID),
			)
		}
	}
}

// ----------------------------------------------------------------------------
// LDAP helpers
// ----------------------------------------------------------------------------

// provisionToAD creates the employee in Active Directory via CreateEmployee.
// All errors are logged and never propagated (best-effort).
func (c *HCMEmployeeConsumer) provisionToAD(
	ctx context.Context,
	log *zap.Logger,
	_ uuid.UUID, // userID — kept for future correlation
	username, email, firstName, lastName, department, title, password string,
) {
	req := &models.CreateEmployeeRequest{
		Username:   username,
		Email:      email,
		FirstName:  firstName,
		LastName:   lastName,
		Department: department,
		Title:      title,
		Password:   password,
	}

	adUser, err := c.ldapService.CreateEmployee(ctx, req)
	if err != nil {
		log.Warn("HCM: hired — failed to provision AD user",
			zap.String("username", username),
			zap.Error(err),
		)
		return
	}

	log.Info("HCM: hired — AD user provisioned",
		zap.String("username", username),
		zap.String("dn", adUser.DN),
	)
}

// updateInAD updates the AD user via UpdateEmployee. All errors are logged.
func (c *HCMEmployeeConsumer) updateInAD(
	ctx context.Context,
	log *zap.Logger,
	userDN, firstName, lastName, department, title, phone string,
) {
	req := &models.UpdateEmployeeRequest{
		UserDN:     userDN,
		FirstName:  &firstName,
		LastName:   &lastName,
		Department: &department,
		Title:      &title,
		Phone:      &phone,
	}

	if err := c.ldapService.UpdateEmployee(ctx, req); err != nil {
		log.Warn("HCM: updated — failed to update AD user",
			zap.String("user_dn", userDN),
			zap.Error(err),
		)
		return
	}

	log.Info("HCM: updated — AD user updated", zap.String("user_dn", userDN))
}

// ----------------------------------------------------------------------------
// Shared helpers
// ----------------------------------------------------------------------------

// resolveUser looks up the IAM user by iam_user_id (UUID) first; falls back to
// email lookup within the tenant when iam_user_id is absent or unparseable.
func (c *HCMEmployeeConsumer) resolveUser(ctx context.Context, tenantID uuid.UUID, iamUserID, email string) (*models.User, error) {
	if iamUserID != "" {
		if user, err := c.resolveUserByID(ctx, iamUserID); err != nil {
			return nil, err
		} else if user != nil {
			return user, nil
		}
	}

	if email == "" {
		return nil, nil
	}

	user, err := c.userRepo.GetByEmail(ctx, tenantID, email)
	if err != nil {
		return nil, fmt.Errorf("resolveUser: GetByEmail: %w", err)
	}

	return user, nil
}

// resolveUserByID looks up a user by the given UUID string.
// Returns (nil, nil) when the UUID is unparseable (treat as absent).
func (c *HCMEmployeeConsumer) resolveUserByID(ctx context.Context, iamUserID string) (*models.User, error) {
	id, err := uuid.Parse(iamUserID)
	if err != nil {
		return nil, nil //nolint:nilerr // unparseable ID treated as absent
	}
	user, err := c.userRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("resolveUser: GetByID: %w", err)
	}
	return user, nil
}

// generateUniqueUsername produces a unique username within the tenant. It
// starts with "first.last" and appends an incrementing suffix on collision.
func (c *HCMEmployeeConsumer) generateUniqueUsername(ctx context.Context, tenantID uuid.UUID, firstName, lastName string) (string, error) {
	base := generateUsername(firstName, lastName)

	candidate := base
	for i := 2; i <= 100; i++ {
		existing, err := c.userRepo.GetByUsername(ctx, tenantID, candidate)
		if err != nil {
			return "", fmt.Errorf("generateUniqueUsername: %w", err)
		}
		if existing == nil {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s%d", base, i)
	}

	// Extremely unlikely: fall back to base + random suffix.
	suffix, _ := rand.Int(rand.Reader, big.NewInt(9999))
	return fmt.Sprintf("%s%d", base, suffix.Int64()), nil
}

// generateUsername converts first and last name into a "first.last" slug.
// Non-alphanumeric characters (except dots) are stripped. The result is at
// least 3 characters by appending "user" when too short.
func generateUsername(firstName, lastName string) string {
	normalise := func(s string) string {
		return strings.ToLower(strings.TrimSpace(s))
	}

	base := normalise(firstName) + "." + normalise(lastName)
	base = regexp.MustCompile(`[^a-z0-9.]`).ReplaceAllString(base, "")

	// Collapse leading/trailing dots.
	base = strings.Trim(base, ".")

	if len(base) < 3 {
		base += auditResourceTypeUser
	}

	return base
}

// generateTemporaryPassword creates a cryptographically random 24-character
// password from a safe character set. The employee will be required to change
// it on first login (MustChangePassword = true).
func generateTemporaryPassword() (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
	b := make([]byte, 24)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", fmt.Errorf("generateTemporaryPassword: %w", err)
		}
		b[i] = chars[n.Int64()]
	}
	return string(b), nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/quota"

	"github.com/dogukanturhal/falcon-id/internal/models"
	"github.com/dogukanturhal/falcon-id/internal/repositories"
	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/crypto"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// userServiceSpiceDBClient is the narrow SpiceDB dependency needed to keep
// role *membership* relationships in sync with iam_user_roles when a tenant
// admin changes a team member's roles via SetUserRoles. *spicedb.Client
// satisfies this interface structurally — see jitSpiceDBClient for the same
// pattern.
//
// Before this was wired in, SetUserRoles only wrote Postgres, published a
// Kafka event nothing consumed for SpiceDB purposes, and invalidated the
// session cache. The ONLY thing that ever wrote the "member" relation SpiceDB
// checks against was SpiceDBReconciler's scheduled pass — SPICEDB_RECONCILER_INTERVAL,
// which defaults to 24h and is not overridden in falcon-id's prod deployment
// (confirmed via the running pod's "Starting SpiceDB reconciler scheduler"
// log line: interval=86400). That meant a freshly assigned role could sit in
// Postgres — and any self-service UI reading Postgres, i.e. GET /api/v1/roles
// via ListManageableSelfService, would show it as assigned — for up to a day
// before SpiceDB-backed authorization (AuthorizationEngine.CheckPermission,
// the sole runtime authority since v2 tokens carry Permissions: nil) actually
// granted anything. Writing synchronously here makes the daily reconciler a
// safety net instead of the primary sync mechanism, matching how
// JITAccessService and TenantBootstrapService already treat SpiceDB as the
// real enforcement boundary rather than a side effect.
type userServiceSpiceDBClient interface {
	WriteUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error)
	DeleteUserRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (string, error)
}

type roleRevokeDrain interface {
	Drain(context.Context, uuid.UUID) error
}

// SetRoleRevokeDrainer wires the post-commit fast path. The repository always
// enqueues removals even when SpiceDB/the drainer is temporarily unavailable.
func (s *UserService) SetRoleRevokeDrainer(d roleRevokeDrain) { s.roleRevokes = d }

// userServiceRoleAssignmentWriter is the optional role_assignment extension
// of userServiceSpiceDBClient (spec 23 section 4.2). *spicedb.Client
// implements it; test fakes that do not simply skip these writes.
type userServiceRoleAssignmentWriter interface {
	WriteRoleAssignment(ctx context.Context, tenantID, userID uuid.UUID, moduleCode string) error
	DeleteRoleAssignment(ctx context.Context, tenantID, userID uuid.UUID, moduleCode string) error
}

// ErrSeatLimitExceeded indicates the tenant's plan has no available seats
// left to create another active user. Matches errors.Is against this
// sentinel, or errors.As against *SeatLimitExceededError for the
// current-usage/limit numbers to surface in an actionable HTTP response
// (see internal/handlers/user_handler.go's Create).
var ErrSeatLimitExceeded = errors.New("seat limit exceeded for tenant plan")

// SeatLimitExceededError wraps ErrSeatLimitExceeded with the current usage
// and effective limit reported by quota-service, so the HTTP layer can
// return a specific, actionable body (current_usage/limit) instead of a
// generic message.
type SeatLimitExceededError struct {
	CurrentUsage int64
	Limit        int64
	Message      string
}

func (e *SeatLimitExceededError) Error() string {
	return fmt.Sprintf("%s (current: %d, limit: %d): %s", ErrSeatLimitExceeded, e.CurrentUsage, e.Limit, e.Message)
}

// Unwrap lets errors.Is(err, ErrSeatLimitExceeded) match a *SeatLimitExceededError.
func (e *SeatLimitExceededError) Unwrap() error {
	return ErrSeatLimitExceeded
}

// RedisCache interface for user lookup caching
type RedisCache interface {
	GetJSON(ctx context.Context, key string) (interface{}, error)
	SetJSON(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// userServiceUserRepo defines the user repository methods needed by UserService.
type userServiceUserRepo interface {
	Create(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error)
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) ([]models.User, int64, error)
	ListTenantMemberCards(ctx context.Context, tenantID, viewerID uuid.UUID, limit, offset int) ([]models.User, int, error)
	AssignRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error)
	GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error)
	UnlockUser(ctx context.Context, userID uuid.UUID) error

	// Admin lifecycle (soft-delete / restore / hard-delete) additions.
	SetDeletionState(ctx context.Context, userID uuid.UUID, activationStatus string, deletionScheduledAt, deletionGracePeriodEndsAt *time.Time, deletionReason *string) error
	CountActiveOwners(ctx context.Context, tenantID uuid.UUID) (int, error)
	HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error)
	HardDeleteUser(ctx context.Context, userID uuid.UUID) (map[string]int, error)
}

// userServiceRoleRepo defines the role repository methods needed by UserService.
type userServiceRoleRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error)
	GetByIDAndTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Role, error)
	GetDefaultRoles(ctx context.Context, tenantID uuid.UUID) ([]models.Role, error)
	GetMaxPriorityForUser(ctx context.Context, userID, tenantID uuid.UUID) (int, error)
}

// userServiceTokenService defines the token service methods needed by UserService.
type userServiceTokenService interface {
	RevokeAllUserOAuthTokens(ctx context.Context, userID uuid.UUID, reason string) error
}

// userServiceBackchannelLogout is the minimal BCL fan-out interface
// UserService needs for the admin-disable cascade. Defined here (not
// imported as the full BackchannelLogoutService type) so the user-
// service unit tests don't need to spin up a token signer + outbox.
type userServiceBackchannelLogout interface {
	NotifyLogout(ctx context.Context, userID uuid.UUID, sessionID string, tenantID uuid.UUID) error
}

// userServiceQuotaClient defines the quota-service methods UserService needs
// for seat-quota enforcement (feat/seat-quota-enforcement). Defined as a
// minimal interface — rather than importing the concrete *quota.QuotaClient
// type directly into the field — so unit tests can stub CheckQuota/
// Increment/Decrement outcomes without a live quota-service; *quota.
// QuotaClient satisfies this interface structurally, no adapter needed.
type userServiceQuotaClient interface {
	MustCheckQuota(ctx context.Context, tenantID uuid.UUID, resourceType quota.ResourceType, amount int64) error
	IncrementUsage(ctx context.Context, tenantID uuid.UUID, resourceType quota.ResourceType, amount int64) (bool, error)
	DecrementUsage(ctx context.Context, tenantID uuid.UUID, resourceType quota.ResourceType, amount int64) error
}

// userServiceAuditService defines the audit service methods needed by UserService.
type userServiceAuditService interface {
	LogUserAction(ctx context.Context, tenantID uuid.UUID, actorID, targetUserID *uuid.UUID, action string, success bool, details map[string]interface{})
}

// userServiceEmailVerifier defines the method needed to send verification emails.
type userServiceEmailVerifier interface {
	SendVerificationEmail(ctx context.Context, userID uuid.UUID) error
}

// userServiceRealmResolver resolves the tenant → realm mapping (Entra ID "home tenant" pattern).
type userServiceRealmResolver interface {
	GetTenantRealm(ctx context.Context, tenantID uuid.UUID) (*models.Realm, error)
}

// UserService is an exported type.
type UserService struct {
	config                  *config.Config
	userRepo                userServiceUserRepo
	roleRepo                userServiceRoleRepo
	tokenService            userServiceTokenService
	auditService            userServiceAuditService
	emailVerifier           userServiceEmailVerifier     // Optional: sends verification email on user create
	realmResolver           userServiceRealmResolver     // Resolves tenant → realm mapping
	eventPublisher          EventPublisher               // Optional: for SpiceDB sync events
	sessionCache            SessionCache                 // Optional: for real-time permission invalidation
	redisCache              RedisCache                   // Optional: for user lookup caching
	integrationBusPublisher UserLifecyclePublisher       // Optional: publishes example.iam.user.* lifecycle events (Kafka, internal/iamevents)
	backchannelLogout       userServiceBackchannelLogout // Optional: fans out OIDC BCL on admin-disable
	accessTerminator        accessTerminator             // Optional: single access-termination path (preferred over the legacy token+BCL fan-out)
	breachChecker           breachChecker                // Optional: HIBP breach-password check on create/set-password
	quotaClient             userServiceQuotaClient       // Optional: enforces/tracks per-tenant seat (resource_type="users") quota
	seatMemberships         SeatMembershipLifecycle      // Optional: keeps tenant_seat_counters in step with disable/restore
	seatFree                SeatFreeChecker              // Optional: employee-class (ESS) users never count against the seat quota
	spicedbClient           userServiceSpiceDBClient     // Optional: synchronous role-membership write on SetUserRoles (see userServiceSpiceDBClient doc)
	roleRevokes             roleRevokeDrain
	sodService              userServiceSoDEvaluator // Optional: ADR-A10 SoD warn-mode evaluation on every role-assignment write
	logger                  *zap.Logger
}

// userServiceSoDEvaluator is the narrow interface UserService depends on
// for ADR-A10 SoD (Separation of Duties) evaluation
// (23-authorization-rbac-abac-rebac.md §5.2: "evaluation on EVERY
// role-assignment write"). Satisfied by *SoDService. Nil-safe: when unset,
// SetUserRoles silently skips SoD evaluation (never blocks the role write
// either way — SoD is warn-mode-only in R1 regardless).
type userServiceSoDEvaluator interface {
	EvaluateUserAsync(ctx context.Context, tenantID, userID uuid.UUID, roleIDs []uuid.UUID)
}

// SetSoDService wires ADR-A10 SoD evaluation into UserService. Safe to
// call with nil (evaluation is then simply skipped).
func (s *UserService) SetSoDService(svc userServiceSoDEvaluator) {
	s.sodService = svc
}

// UserEventPayload is the event payload for user created/updated events published
// to the integration bus for downstream HCM employee sync.
type UserEventPayload struct {
	UserID      string `json:"user_id"`
	TenantID    string `json:"tenant_id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	DisplayName string `json:"display_name"`
	Phone       string `json:"phone"`
	IsActive    bool   `json:"is_active"`
	// EmailVerified lets HCM auto-link an employee by email only when the
	// mailbox ownership was proven (xm F3).
	EmailVerified bool `json:"email_verified"`
	// Source identifies the origin of this event. It is always set to "iam" so
	// that the HCM employee consumer can skip events it did not originate from
	// HCM, preventing circular synchronisation loops.
	Source string `json:"source"`
}

// UserStatusEventPayload is the event payload for user status-change events
// (locked, unlocked, deleted) published to the integration bus.
type UserStatusEventPayload struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
	IsActive bool   `json:"is_active"`
	IsLocked bool   `json:"is_locked"`
	Action   string `json:"action"` // "deleted", "locked", "unlocked", "admin_soft_deleted", "admin_restored"
	// Source identifies the origin of this event. Always "iam" so that
	// downstream consumers can detect events originating from this service
	// and skip them to prevent circular synchronisation loops.
	Source string `json:"source"`
}

// NewUserService is an exported function.
func NewUserService(
	cfg *config.Config,
	userRepo userServiceUserRepo,
	roleRepo userServiceRoleRepo,
	tokenService userServiceTokenService,
	auditService userServiceAuditService,
) *UserService {
	return &UserService{
		config:       cfg,
		userRepo:     userRepo,
		roleRepo:     roleRepo,
		tokenService: tokenService,
		auditService: auditService,
		logger:       logger.Log,
	}
}

// SetEventPublisher sets the event publisher for SpiceDB sync
func (s *UserService) SetEventPublisher(publisher EventPublisher) {
	s.eventPublisher = publisher
}

// SetSessionCache sets the session cache for real-time permission invalidation
func (s *UserService) SetSessionCache(cache SessionCache) {
	s.sessionCache = cache
}

// SetRedisCache sets the Redis cache for user lookup caching
func (s *UserService) SetRedisCache(cache RedisCache) {
	s.redisCache = cache
}

// SetSpiceDBClient wires the SpiceDB dependency used by SetUserRoles to
// write role-membership changes synchronously instead of relying solely on
// the (24h-interval) SpiceDBReconciler. Optional: when unset, SetUserRoles
// falls back to the pre-existing Postgres-only + reconciler-repair behavior.
func (s *UserService) SetSpiceDBClient(client userServiceSpiceDBClient) {
	s.spicedbClient = client
}

// SetEmailVerifier sets the email verifier for sending verification emails on user creation
func (s *UserService) SetEmailVerifier(verifier userServiceEmailVerifier) {
	s.emailVerifier = verifier
}

// SetRealmResolver sets the realm resolver for tenant → realm mapping during user creation
func (s *UserService) SetRealmResolver(resolver userServiceRealmResolver) {
	s.realmResolver = resolver
}

// SetQuotaClient sets the quota-service client used to enforce and track
// per-tenant seat usage (resource_type="users") around Create/Delete. Left
// nil (the zero value) disables seat-quota enforcement entirely — Create
// and Delete behave exactly as before this feature, matching the optional-
// dependency pattern of the other Set* wirings above. Accepts any
// userServiceQuotaClient implementation — production wiring passes a
// *quota.QuotaClient (cmd/services.go's buildQuotaClient), tests pass a
// stub.
func (s *UserService) SetQuotaClient(client userServiceQuotaClient) {
	s.quotaClient = client
}

// SeatFreeChecker reports whether a user holds a seat-free (employee-class) membership; the quota
// decrement/increment paths skip such users because they were never counted.
type SeatFreeChecker interface {
	IsSeatFree(ctx context.Context, tenantID, userID uuid.UUID) (bool, error)
}

// SetSeatFreeChecker wires the employee-seat lookup. nil (the zero value) treats every user as seat-consuming.
func (s *UserService) SetSeatFreeChecker(c SeatFreeChecker) {
	s.seatFree = c
}

// isSeatFree is fail-toward-counting: a lookup error is logged and the user is treated as seat-consuming (the
// seat-quota reconciler corrects any resulting drift).
func (s *UserService) isSeatFree(ctx context.Context, tenantID, userID uuid.UUID) bool {
	if s.seatFree == nil {
		return false
	}
	free, err := s.seatFree.IsSeatFree(ctx, tenantID, userID)
	if err != nil {
		s.logger.Warn("seat-free lookup failed; treating the user as seat-consuming",
			zap.String("tenant_id", tenantID.String()), zap.String("user_id", userID.String()), zap.Error(err))
		return false
	}
	return free
}

// SeatMembershipLifecycle moves the seat ledger with a user's active state: Deactivate frees a member seat once,
// Reactivate re-occupies one and returns repositories.ErrSeatLimitReached when the tenant is full.
type SeatMembershipLifecycle interface {
	Deactivate(ctx context.Context, tenantID, userID uuid.UUID) (bool, error)
	Reactivate(ctx context.Context, tenantID, userID uuid.UUID) (bool, error)
}

// SetSeatMembershipLifecycle wires the seat-ledger hooks of disable/restore. nil (the zero value) skips them.
func (s *UserService) SetSeatMembershipLifecycle(m SeatMembershipLifecycle) { s.seatMemberships = m }

// occupyMemberSeat re-occupies the user's member seat before a reactivation is persisted; a full tenant yields
// repositories.ErrSeatLimitReached (callers map it to 409).
func (s *UserService) occupyMemberSeat(ctx context.Context, tenantID, userID uuid.UUID) error {
	if s.seatMemberships == nil {
		return nil
	}
	if _, err := s.seatMemberships.Reactivate(ctx, tenantID, userID); err != nil {
		if errors.Is(err, repositories.ErrSeatLimitReached) {
			return err
		}
		return fmt.Errorf("occupy seat: %w", err)
	}
	return nil
}

// releaseMemberSeat frees the user's member seat after a disable/soft-delete committed. Best-effort and
// idempotent (only an active membership releases); a failure is logged and the seat-quota reconciler recomputes it.
func (s *UserService) releaseMemberSeat(ctx context.Context, tenantID, userID uuid.UUID) {
	if s.seatMemberships == nil {
		return
	}
	if _, err := s.seatMemberships.Deactivate(ctx, tenantID, userID); err != nil {
		s.logger.Warn("failed to release member seat; reconciler will recompute",
			zap.String("tenant_id", tenantID.String()), zap.String("user_id", userID.String()), zap.Error(err))
	}
}

// SetAccessTerminator wires the single access-termination path used by
// admin-disable and hard-delete; when set it supersedes the legacy
// token-revoke + BCL fan-out below.
func (s *UserService) SetAccessTerminator(t accessTerminator) {
	s.accessTerminator = t
}

// SetBackchannelLogout wires the OIDC Back-Channel Logout fan-out so
// that admin-disable cascades evict every IdP session (and via the
// per-RP receiver chain, every downstream RP session) without having
// to wait for natural token expiry.
//
// Without this dependency, Update() falls back to RevokeAllUserOAuthTokens
// alone — which invalidates server-side refresh tokens but leaves the
// downstream RPs (Talon, accounts BFF, gitlab/harbor shims) holding
// live cookies until their TTL expires. The boot-hook NIST-AAL2 TTL
// matrix bounds that lag at 15min for admin-tier RPs, but BCL fan-out
// closes it to <5s.
func (s *UserService) SetBackchannelLogout(bcl userServiceBackchannelLogout) {
	s.backchannelLogout = bcl
}

// UserLifecyclePublisher publishes example.iam.user.{created,updated,status-changed}.
// Production implementation: internal/iamevents.Publisher (Kafka; consumed by
// example-business HR IamUserEventConsumer).
type UserLifecyclePublisher interface {
	PublishEvent(ctx context.Context, tenantID, eventType string, payload interface{}) error
}

// SetIntegrationBusPublisher sets the publisher used to propagate user
// lifecycle events (create / update / status) to downstream consumers. It is
// optional; when nil, no lifecycle events are emitted.
func (s *UserService) SetIntegrationBusPublisher(p UserLifecyclePublisher) {
	s.integrationBusPublisher = p
}

// SetBreachChecker wires the HIBP breach-password check (ASVS V6 / NIST
// 800-63B) into Create and SetPassword. Optional + nil-safe: when unwired the
// checks short-circuit (no-op).
func (s *UserService) SetBreachChecker(c breachChecker) {
	s.breachChecker = c
}

// publishUserRoleEvent publishes a user role assignment/revocation event
func (s *UserService) publishUserRoleEvent(ctx context.Context, topic string, tenantID, userID, roleID uuid.UUID) {
	if s.eventPublisher == nil {
		return
	}

	payload := IAMEventPayload{
		TenantID: tenantID,
		UserID:   &userID,
		RoleID:   &roleID,
	}

	if err := s.eventPublisher.PublishEvent(ctx, topic, userID.String(), payload); err != nil {
		logger.Warn("Failed to publish user role event",
			zap.String("topic", topic),
			zap.String("user_id", userID.String()),
			zap.String("role_id", roleID.String()),
			zap.Error(err),
		)
	}
}

// lifecyclePublishTimeout bounds one fire-and-forget lifecycle publish.
const lifecyclePublishTimeout = 10 * time.Second

// publishUserLifecycleEvent publishes a example.iam.user.* event to the integration
// bus. It is always called inside a goroutine (fire-and-forget) so it uses
// context.Background() rather than the request context, which may already be
// cancelled by the time the goroutine executes.
func (s *UserService) publishUserLifecycleEvent(user *models.User, eventType string) {
	if s.integrationBusPublisher == nil {
		return
	}

	userID := user.ID.String()
	tenantID := user.TenantID.String()

	go func() {
		payload := UserEventPayload{
			UserID:        userID,
			TenantID:      tenantID,
			Username:      user.Username,
			Email:         user.Email,
			IsActive:      user.IsActive,
			EmailVerified: user.IsEmailVerified,
			// Source is always "iam" so downstream consumers (e.g. HCM employee
			// consumer) can detect events originating from this service and skip
			// them to prevent circular synchronisation loops.
			Source: "iam",
		}
		if user.FirstName != nil {
			payload.FirstName = *user.FirstName
		}
		if user.LastName != nil {
			payload.LastName = *user.LastName
		}
		if user.DisplayName != nil {
			payload.DisplayName = *user.DisplayName
		}
		if user.Phone != nil {
			payload.Phone = *user.Phone
		}

		pubCtx, cancel := context.WithTimeout(context.Background(), lifecyclePublishTimeout)
		defer cancel()
		if err := s.integrationBusPublisher.PublishEvent(
			pubCtx,
			tenantID,
			eventType,
			payload,
		); err != nil {
			s.logger.Warn("Failed to publish user lifecycle event to integration bus",
				zap.String("event_type", eventType),
				zap.String("user_id", userID),
				zap.Error(err),
			)
		}
	}()
}

// publishUserStatusEvent publishes a example.iam.user.status-changed event to
// the integration bus for lock / unlock / delete operations.
func (s *UserService) publishUserStatusEvent(user *models.User, action string) {
	if s.integrationBusPublisher == nil {
		return
	}

	userID := user.ID.String()
	tenantID := user.TenantID.String()

	go func() {
		payload := UserStatusEventPayload{
			UserID:   userID,
			TenantID: tenantID,
			Email:    user.Email,
			IsActive: user.IsActive,
			IsLocked: user.IsLocked,
			Action:   action,
			Source:   "iam",
		}

		pubCtx, cancel := context.WithTimeout(context.Background(), lifecyclePublishTimeout)
		defer cancel()
		if err := s.integrationBusPublisher.PublishEvent(
			pubCtx,
			tenantID,
			"example.iam.user.status-changed",
			payload,
		); err != nil {
			s.logger.Warn("Failed to publish user status event to integration bus",
				zap.String("action", action),
				zap.String("user_id", userID),
				zap.Error(err),
			)
		}
	}()
}

// PreparedSignupCredential is an opaque, password-bound result of the one
// authoritative self-service signup policy decision. Its fields deliberately
// remain private so callers cannot forge a bypass for normal user creation.
type PreparedSignupCredential struct {
	passwordHash   string
	passwordDigest [sha256.Size]byte
}

// PrepareSignupCredential validates and hashes a self-service signup password
// before tenant provisioning. Breach-check outages retain the configured
// best-effort behavior through ValidateSignupPassword.
func (s *UserService) PrepareSignupCredential(ctx context.Context, password string) (*PreparedSignupCredential, error) {
	if err := s.ValidateSignupPassword(ctx, password); err != nil {
		return nil, err
	}
	hash, err := crypto.HashPassword(password, nil)
	if err != nil {
		return nil, fmt.Errorf("hash signup password: %w", err)
	}
	return &PreparedSignupCredential{passwordHash: hash, passwordDigest: sha256.Sum256([]byte(password))}, nil
}

// Create creates a new user and independently enforces normal local password
// policy. It is intentionally separate from the prepared signup path.
func (s *UserService) Create(ctx context.Context, req *models.CreateUserRequest, createdBy *uuid.UUID) (*models.UserResponse, error) {
	var passwordHash *string
	if req.Password != "" {
		policy := s.localPasswordPolicy()
		if err := crypto.ValidatePassword(req.Password, policy); err != nil {
			return nil, fmt.Errorf("Create: password validation failed: %w", err)
		}
		if err := assertPasswordNotBreached(ctx, s.breachChecker, req.Password); err != nil {
			return nil, fmt.Errorf("Create: %w", err)
		}
		hash, err := crypto.HashPassword(req.Password, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		passwordHash = &hash
	}
	return s.create(ctx, req, createdBy, passwordHash, false)
}

// CreateSeatFree creates an employee-class (ESS) user: no quota check and no usage increment, and no password (the
// account is activated through a password-setup invitation). The caller must record the employee membership.
func (s *UserService) CreateSeatFree(ctx context.Context, req *models.CreateUserRequest, createdBy *uuid.UUID) (*models.UserResponse, error) {
	return s.create(ctx, req, createdBy, nil, true)
}

// CreatePreparedForSignup persists a credential that was already validated
// before provisioning. The digest binds it to this exact request password.
func (s *UserService) CreatePreparedForSignup(ctx context.Context, req *models.CreateUserRequest, credential *PreparedSignupCredential) (*models.UserResponse, error) {
	digest := sha256.Sum256([]byte(req.Password))
	if credential == nil || credential.passwordHash == "" || req.Password == "" ||
		subtle.ConstantTimeCompare(credential.passwordDigest[:], digest[:]) != 1 {
		return nil, errors.New("invalid prepared signup credential")
	}
	return s.create(ctx, req, nil, &credential.passwordHash, false)
}

func (s *UserService) create(ctx context.Context, req *models.CreateUserRequest, createdBy *uuid.UUID, passwordHash *string, seatFree bool) (*models.UserResponse, error) {
	// Check if username already exists
	existing, err := s.userRepo.GetByUsername(ctx, req.TenantID, req.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to check username: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Check if email already exists
	existing, err = s.userRepo.GetByEmail(ctx, req.TenantID, req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to check email: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("email already exists")
	}

	user := &models.User{
		TenantID:         req.TenantID,
		Username:         req.Username,
		Email:            req.Email,
		FirstName:        req.FirstName,
		LastName:         req.LastName,
		DisplayName:      req.DisplayName,
		Phone:            req.Phone,
		FederationType:   req.FederationType,
		FederationID:     req.FederationID,
		FederationSource: req.FederationSource,
		IsActive:         true,
		IsEmailVerified:  req.EmailVerified,
		CreatedBy:        createdBy,
	}

	// Realm resolution — fail-closed (OWASP Multi-Tenant Cheat Sheet,
	// RFC 9700 §4 OAuth 2.0 Security BCP, Microsoft Entra multitenant
	// guidance). The previous implementation defaulted to
	// `models.DefaultRealmID` when the resolver returned nil — that is
	// a documented anti-pattern: a tenant that lost its realm
	// assignment would silently land in the shared customer realm,
	// crossing isolation boundaries. The class corresponds to the
	// Storm-0558 cross-tenant impersonation post-mortem and to
	// CWE-1259 / CWE-284 (improper authorization scope).
	//
	// Three accepted paths in decreasing precedence:
	//
	//   1. req.RealmID explicit  — caller threaded the realm
	//      deterministically (e.g. admin_bootstrap maps the
	//      exampletenant tenant → WellKnownRealmPlatform). The
	//      caller is responsible for verifying the realm exists.
	//
	//   2. realmResolver lookup  — production runtime path; the
	//      tenant has an explicit assignment in realm_tenants.
	//
	//   3. Hard fail            — no implicit defaults. The repository
	//      `realm_id is required` precondition is intentional and the
	//      service layer surfaces the same fail-closed error.
	if req.RealmID != nil && *req.RealmID != uuid.Nil {
		user.RealmID = *req.RealmID
	} else if s.realmResolver != nil {
		realm, err := s.realmResolver.GetTenantRealm(ctx, req.TenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve realm for tenant: %w", err)
		}
		if realm != nil {
			user.RealmID = realm.ID
		}
	}
	if user.RealmID == uuid.Nil {
		return nil, fmt.Errorf("realm_id resolution failed for tenant %s: caller must thread req.RealmID explicitly or assign the tenant to a realm via realm_tenants", req.TenantID)
	}

	if passwordHash != nil {
		user.PasswordHash = passwordHash
	}

	// Seat-quota enforcement (feat/seat-quota-enforcement): check BEFORE the
	// write so an over-limit tenant never gets the row in the first place.
	// quotaClient is nil unless SetQuotaClient was called (cmd/services.go
	// wiring) — nil-safe no-op for callers/tests that don't wire it, e.g.
	// admin bootstrap and every existing unit test that constructs
	// UserService directly.
	if s.quotaClient != nil && s.config.QuotaEnforcementEnabled && !seatFree {
		if err := s.quotaClient.MustCheckQuota(ctx, req.TenantID, quota.ResourceTypeUsers, 1); err != nil {
			var quotaExceeded *quota.QuotaExceededError
			if quota.IsQuotaExceededError(err) && errors.As(err, &quotaExceeded) {
				return nil, &SeatLimitExceededError{
					CurrentUsage: quotaExceeded.CurrentUsage,
					Limit:        quotaExceeded.Limit,
					Message:      quotaExceeded.Message,
				}
			}
			// MustCheckQuota failed for a reason OTHER than quota being
			// exceeded (quota-service network error / timeout / non-2xx
			// that CheckQuota itself did not already normalize to
			// Allowed=true — see platform-shared/quota's fail-open comment
			// on transport/5xx). Fail-closed by default: silently granting
			// unlimited seats during a quota-service outage is the worse
			// failure mode for a paid seat limit. QuotaCheckFailOpen is the
			// documented, ops-controlled escape hatch if quota-service
			// instability starts blocking all signups.
			if s.config.QuotaCheckFailOpen {
				s.logger.Warn("seat quota check failed, failing OPEN (QUOTA_CHECK_FAIL_OPEN=true) — signup allowed WITHOUT a confirmed seat check",
					zap.String("tenant_id", req.TenantID.String()),
					zap.Error(err),
				)
			} else {
				s.logger.Error("seat quota check failed, failing CLOSED (QUOTA_CHECK_FAIL_OPEN=false) — signup denied because quota-service could not confirm an available seat",
					zap.String("tenant_id", req.TenantID.String()),
					zap.Error(err),
				)
				return nil, fmt.Errorf("Create: seat quota check failed: %w", err)
			}
		}
	}

	// Create user
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Assign roles
	if len(req.RoleIDs) > 0 {
		if err := s.userRepo.AssignRoles(ctx, user.ID, req.RoleIDs, createdBy); err != nil {
			return nil, fmt.Errorf("failed to assign roles: %w", err)
		}
	} else {
		// Assign default roles
		defaultRoles, err := s.roleRepo.GetDefaultRoles(ctx, req.TenantID)
		if err == nil && len(defaultRoles) > 0 {
			roleIDs := make([]uuid.UUID, len(defaultRoles))
			for i, r := range defaultRoles {
				roleIDs[i] = r.ID
			}
			_ = s.userRepo.AssignRoles(ctx, user.ID, roleIDs, createdBy)
		}
	}

	// Get roles and permissions for response
	roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
	if err != nil {
		s.logger.Warn("failed to get user roles", zap.String("user_id", user.ID.String()), zap.Error(err))
	}
	permissions, err := s.userRepo.GetUserPermissions(ctx, user.ID)
	if err != nil {
		s.logger.Warn("failed to get user permissions", zap.String("user_id", user.ID.String()), zap.Error(err))
	}
	user.Roles = roles
	user.Permissions = permissions

	// Audit log
	s.auditService.LogUserAction(ctx, req.TenantID, createdBy, &user.ID, "user_create", true, nil)

	// Publish user created event to integration bus (fire-and-forget, best-effort)
	s.publishUserLifecycleEvent(user, "example.iam.user.created")

	// Record seat usage against the tenant's plan (fire-and-forget,
	// best-effort — same posture as publishUserLifecycleEvent above). The
	// seat was already confirmed available by MustCheckQuota above; this
	// just makes it count. A failure here does not fail the request — it
	// would deny the user something already created — but is logged loudly
	// since a persistent failure means usage drifts from reality.
	if s.quotaClient != nil && s.config.QuotaEnforcementEnabled && !seatFree {
		go func(tenantID uuid.UUID) { //nolint:gosec // goroutine must outlive request context
			incCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := s.quotaClient.IncrementUsage(incCtx, tenantID, quota.ResourceTypeUsers, 1); err != nil {
				s.logger.Warn("failed to increment seat usage after user create",
					zap.String("tenant_id", tenantID.String()),
					zap.Error(err),
				)
			}
		}(req.TenantID)
	}

	// Send verification email asynchronously (fire-and-forget)
	if s.emailVerifier != nil && user.Email != "" && !user.IsEmailVerified {
		go func(userID uuid.UUID) { //nolint:gosec // goroutine must outlive request context
			verifyCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := s.emailVerifier.SendVerificationEmail(verifyCtx, userID); err != nil {
				s.logger.Warn("Failed to send verification email for new user",
					zap.String("user_id", userID.String()),
					zap.Error(err),
				)
			} else {
				s.logger.Info("Verification email sent for new user",
					zap.String("user_id", userID.String()),
				)
			}
		}(user.ID)
	}

	return user.ToResponse(), nil
}

// getCachedUserResponse attempts to retrieve a cached UserResponse from Redis.
func (s *UserService) getCachedUserResponse(ctx context.Context, id uuid.UUID) (*models.UserResponse, bool) {
	if s.redisCache == nil {
		return nil, false
	}
	cacheKey := fmt.Sprintf("iam:user:%s", id.String())
	cached, err := s.redisCache.GetJSON(ctx, cacheKey)
	if err != nil || cached == nil {
		return nil, false
	}
	data, ok := cached.(map[string]interface{})
	if !ok {
		return nil, false
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, false
	}
	var userResp models.UserResponse
	if json.Unmarshal(jsonBytes, &userResp) != nil {
		return nil, false
	}
	return &userResp, true
}

// GetByID gets a user by ID
func (s *UserService) GetByID(ctx context.Context, id uuid.UUID) (*models.UserResponse, error) {
	// Try cache first if available
	if cached, ok := s.getCachedUserResponse(ctx, id); ok {
		return cached, nil
	}

	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("GetByID: failed to get user: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Get roles and permissions
	roles, err := s.userRepo.GetUserRoles(ctx, id)
	if err != nil {
		s.logger.Warn("failed to get user roles", zap.String("user_id", id.String()), zap.Error(err))
	}
	permissions, err := s.userRepo.GetUserPermissions(ctx, id)
	if err != nil {
		s.logger.Warn("failed to get user permissions", zap.String("user_id", id.String()), zap.Error(err))
	}
	user.Roles = roles
	user.Permissions = permissions

	response := user.ToResponse()

	// Cache result for 5 minutes
	if s.redisCache != nil {
		cacheKey := fmt.Sprintf("iam:user:%s", id.String())
		_ = s.redisCache.SetJSON(ctx, cacheKey, response, 5*time.Minute)
	}

	return response, nil
}

// Update updates a user
func (s *UserService) Update(ctx context.Context, id uuid.UUID, req *models.UpdateUserRequest, updatedBy *uuid.UUID) (*models.UserResponse, error) {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("Update: failed to get user: %w", err)
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	// Capture the pre-update IsActive value so we can detect the
	// active→disabled transition AFTER the row update commits. The
	// transition fires the RFC 7009 + BCL fan-out cascade — Phase 5a
	// of the 2026-05-10 tier-1 SLO restoration plan.
	wasActive := user.IsActive

	// Update fields
	if req.FirstName != nil {
		user.FirstName = req.FirstName
	}
	if req.LastName != nil {
		user.LastName = req.LastName
	}
	if req.DisplayName != nil {
		user.DisplayName = req.DisplayName
	}
	if req.Phone != nil {
		user.Phone = req.Phone
	}
	if req.AvatarURL != nil {
		user.AvatarURL = req.AvatarURL
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	if req.MustChangePassword != nil {
		user.MustChangePassword = *req.MustChangePassword
	}

	user.UpdatedBy = updatedBy

	// Re-enabling a disabled member re-occupies a seat first, so a full tenant is refused before anything changes.
	reoccupied := !wasActive && user.IsActive
	if reoccupied {
		if err := s.occupyMemberSeat(ctx, user.TenantID, id); err != nil {
			return nil, fmt.Errorf("Update: %w", err)
		}
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		if reoccupied {
			s.releaseMemberSeat(ctx, user.TenantID, id)
		}
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Admin-disable cascade (Phase 5a): when an admin transitions a
	// user from active→disabled, immediately evict every cached
	// session and fan out OIDC Back-Channel Logout to every RP that
	// has a backchannel_logout_uri seeded. Without this, the user's
	// OAuth refresh + access tokens remain valid until natural TTL
	// expiry (15min admin-tier / 60min customer-tier per the NIST AAL2
	// matrix in cmd/oauth_client_slo_bootstrap.go) — bounded but not
	// instant.
	//
	// Both calls are best-effort: a failure here is logged but does
	// NOT roll back the is_active=false write. The user's flag is the
	// authoritative state; subsequent token refresh attempts will fail
	// regardless of whether revocation reached every RP. BCL closes
	// the user-side latency to <5s when the cascade succeeds.
	if wasActive && !user.IsActive {
		s.releaseMemberSeat(ctx, user.TenantID, id)
		s.cascadeAdminDisable(ctx, user)
	}
	if !wasActive && user.IsActive && s.accessTerminator != nil {
		// The disable wrote a short-lived user-wide blacklist; drop it so the
		// re-enabled user can log in immediately.
		s.accessTerminator.ClearUserBlock(ctx, id)
	}

	// Update roles if provided
	if req.RoleIDs != nil {
		if err := s.userRepo.AssignRoles(ctx, id, req.RoleIDs, updatedBy); err != nil {
			return nil, fmt.Errorf("failed to update roles: %w", err)
		}
	}

	// Get updated roles and permissions
	roles, err := s.userRepo.GetUserRoles(ctx, id)
	if err != nil {
		s.logger.Warn("failed to get user roles", zap.String("user_id", id.String()), zap.Error(err))
	}
	permissions, err := s.userRepo.GetUserPermissions(ctx, id)
	if err != nil {
		s.logger.Warn("failed to get user permissions", zap.String("user_id", id.String()), zap.Error(err))
	}
	user.Roles = roles
	user.Permissions = permissions

	// Audit log
	s.auditService.LogUserAction(ctx, user.TenantID, updatedBy, &user.ID, "user_update", true, nil)

	// Publish user updated event to integration bus (fire-and-forget, best-effort)
	s.publishUserLifecycleEvent(user, "example.iam.user.updated")

	// Invalidate cache
	if s.redisCache != nil {
		cacheKey := fmt.Sprintf("iam:user:%s", id.String())
		_ = s.redisCache.Delete(ctx, cacheKey)
	}

	return user.ToResponse(), nil
}

// cascadeAdminDisable runs the post-Update fan-out for the
// active→disabled user transition. RFC 7009 token revocation +
// OIDC Back-Channel Logout, both best-effort.
//
// Why not block Update on success: the authoritative state is the
// is_active=false row — subsequent /oauth/refresh + /oauth/userinfo
// requests fail regardless of whether the cascade reached every RP.
// BCL is a latency optimisation, not a correctness primitive.
//
// Why context.Background(): the request-scoped context may have a
// short deadline (HTTP request timeout). The user-disable write has
// already committed; we want the fan-out to complete even if the
// admin's HTTP request closes before the RPC finishes.
func (s *UserService) cascadeAdminDisable(ctx context.Context, user *models.User) {
	// Detach from the request ctx so a slow drainer enqueue (or BCL
	// HTTP) doesn't fail because the admin's HTTP request closed. Use
	// the parent request's tracing context if any; here we use a
	// fresh background context.
	_ = ctx // intentionally unused; the parent context's deadline
	// would prematurely cancel a slow fan-out.
	bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if s.accessTerminator != nil {
		// Ends sessions, OAuth tokens, SSO cookies, blacklists JWTs, fans out
		// BCL and publishes CAE in one place (best-effort per step).
		if err := s.accessTerminator.TerminateUserAccess(bgCtx, user.ID, user.TenantID, "admin_disable", nil); err != nil {
			s.logger.Error("UserService.cascadeAdminDisable: access termination incomplete",
				zap.String("user_id", user.ID.String()), zap.Error(err))
		}
		if s.auditService != nil {
			s.auditService.LogUserAction(bgCtx, user.TenantID, user.UpdatedBy, &user.ID, "user_admin_disabled", true, nil)
		}
		return
	}

	if s.tokenService != nil {
		if err := s.tokenService.RevokeAllUserOAuthTokens(bgCtx, user.ID, "admin_disable"); err != nil {
			s.logger.Error("UserService.cascadeAdminDisable: RevokeAllUserOAuthTokens failed",
				zap.String("user_id", user.ID.String()),
				zap.Error(err),
			)
		} else {
			s.logger.Info("UserService.cascadeAdminDisable: revoked all OAuth tokens for user",
				zap.String("user_id", user.ID.String()),
			)
		}
	} else {
		s.logger.Warn("UserService.cascadeAdminDisable: tokenService not wired, skipping token revocation",
			zap.String("user_id", user.ID.String()),
		)
	}

	if s.backchannelLogout != nil {
		// sub-wide cascade — empty sessionID parameter signals "every
		// session for this sub" to BackchannelLogoutService. The
		// receiver-side cascade then fans out via talon:revoke-by-sub
		// and accounts BFF's bcl:sub:<sub> tombstone.
		if err := s.backchannelLogout.NotifyLogout(bgCtx, user.ID, "", user.TenantID); err != nil {
			s.logger.Error("UserService.cascadeAdminDisable: BCL fan-out failed",
				zap.String("user_id", user.ID.String()),
				zap.String("tenant_id", user.TenantID.String()),
				zap.Error(err),
			)
		} else {
			s.logger.Info("UserService.cascadeAdminDisable: BCL fan-out enqueued",
				zap.String("user_id", user.ID.String()),
				zap.String("tenant_id", user.TenantID.String()),
			)
		}
	} else {
		s.logger.Warn("UserService.cascadeAdminDisable: backchannelLogout not wired, skipping BCL fan-out",
			zap.String("user_id", user.ID.String()),
		)
	}

	if s.auditService != nil {
		s.auditService.LogUserAction(bgCtx, user.TenantID, user.UpdatedBy, &user.ID, "user_admin_disabled", true, nil)
	}
}

// Delete deletes a user
func (s *UserService) Delete(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("Delete: failed to get user: %w", err)
	}

	if user == nil {
		return fmt.Errorf("user not found")
	}

	seatFree := s.isSeatFree(ctx, user.TenantID, id) // before the delete: the membership row may go with the user
	if err := s.userRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	// Audit log
	s.auditService.LogUserAction(ctx, user.TenantID, deletedBy, &id, "user_delete", true, nil)

	// Publish user deleted status event to integration bus (fire-and-forget, best-effort)
	s.publishUserStatusEvent(user, "deleted")

	// Release the seat back to the tenant's plan (fire-and-forget,
	// best-effort — same posture as the lifecycle-event publishes above).
	if s.quotaClient != nil && s.config.QuotaEnforcementEnabled && !seatFree {
		go func(tenantID uuid.UUID) { //nolint:gosec // goroutine must outlive request context
			decCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := s.quotaClient.DecrementUsage(decCtx, tenantID, quota.ResourceTypeUsers, 1); err != nil {
				s.logger.Warn("failed to decrement seat usage after user delete",
					zap.String("tenant_id", tenantID.String()),
					zap.Error(err),
				)
			}
		}(user.TenantID)
	}

	// Invalidate cache
	if s.redisCache != nil {
		cacheKey := fmt.Sprintf("iam:user:%s", id.String())
		_ = s.redisCache.Delete(ctx, cacheKey)
	}

	return nil
}

// List lists users for a tenant
func (s *UserService) List(ctx context.Context, tenantID uuid.UUID, page, pageSize int, search string) (*models.UserListResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	users, total, err := s.userRepo.List(ctx, tenantID, page, pageSize, search)
	if err != nil {
		return nil, fmt.Errorf("List: failed to list users: %w", err)
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	userResponses := make([]models.UserResponse, len(users))
	for i, user := range users {
		// Get roles for each user
		roles, err := s.userRepo.GetUserRoles(ctx, user.ID)
		if err != nil {
			s.logger.Warn("failed to get user roles", zap.String("user_id", user.ID.String()), zap.Error(err))
		}
		user.Roles = roles
		userResponses[i] = *user.ToResponse()
	}

	return &models.UserListResponse{
		Users:      userResponses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// SetPassword sets a new password for a user (admin action)
func (s *UserService) SetPassword(ctx context.Context, id uuid.UUID, newPassword string, mustChange bool, setBy *uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("SetPassword: failed to get user: %w", err)
	}

	if user == nil {
		return fmt.Errorf("user not found")
	}

	// Check if user is federated
	if user.FederationType != nil && *user.FederationType == federationTypeLDAP {
		return fmt.Errorf("cannot set password for LDAP users")
	}

	// Validate password
	policy := &crypto.PasswordPolicy{
		MinLength:      s.config.PasswordMinLength,
		RequireUpper:   s.config.PasswordRequireUpper,
		RequireLower:   s.config.PasswordRequireLower,
		RequireDigit:   s.config.PasswordRequireDigit,
		RequireSpecial: s.config.PasswordRequireSpecial,
	}

	if err := crypto.ValidatePassword(newPassword, policy); err != nil {
		return fmt.Errorf("SetPassword: password validation failed: %w", err)
	}

	// ASVS V6 / NIST 800-63B — reject breached passwords on set-password.
	if err := assertPasswordNotBreached(ctx, s.breachChecker, newPassword); err != nil {
		return fmt.Errorf("SetPassword: %w", err)
	}

	// Hash password
	hash, err := crypto.HashPassword(newPassword, nil)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user.PasswordHash = &hash
	now := time.Now()
	user.PasswordChangedAt = &now
	user.MustChangePassword = mustChange
	user.UpdatedBy = setBy

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Revoke OAuth tokens — auth-service refresh tokens were removed in
	// Phase 3 (mig 233), so the OAuth-token sweep is the canonical
	// post-password-set revoke path. Best-effort; failures here don't
	// block the password update from completing.
	if s.accessTerminator != nil {
		termCtx, cancel := detachedTerminationCtx()
		defer cancel()
		_ = s.accessTerminator.TerminateUserAccessWith(termCtx, id, user.TenantID, "password_reset", TerminateOptions{})
	} else {
		_ = s.tokenService.RevokeAllUserOAuthTokens(ctx, id, "password_reset")
	}

	// Audit log
	s.auditService.LogUserAction(ctx, user.TenantID, setBy, &id, "user_password_set", true, nil)

	return nil
}

// Lock locks a user account
func (s *UserService) Lock(ctx context.Context, id uuid.UUID, reason string, lockedBy *uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("Lock: failed to get user: %w", err)
	}

	if user == nil {
		return fmt.Errorf("user not found")
	}

	user.IsLocked = true
	user.LockReason = &reason
	now := time.Now()
	user.LockedAt = &now
	user.UpdatedBy = lockedBy

	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to lock user: %w", err)
	}

	// Audit log
	s.auditService.LogUserAction(ctx, user.TenantID, lockedBy, &id, "user_lock", true, map[string]interface{}{"reason": reason})

	// Publish user locked status event to integration bus (fire-and-forget, best-effort)
	s.publishUserStatusEvent(user, "locked")

	return nil
}

// Unlock unlocks a user account
func (s *UserService) Unlock(ctx context.Context, id uuid.UUID, unlockedBy *uuid.UUID) error {
	if err := s.userRepo.UnlockUser(ctx, id); err != nil {
		return fmt.Errorf("failed to unlock user: %w", err)
	}

	user, _ := s.userRepo.GetByID(ctx, id)
	if user != nil {
		s.auditService.LogUserAction(ctx, user.TenantID, unlockedBy, &id, "user_unlock", true, nil)

		// Publish user unlocked status event to integration bus (fire-and-forget, best-effort)
		s.publishUserStatusEvent(user, "unlocked")
	}

	return nil
}

// GetUserRoles gets roles for a user
func (s *UserService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.RoleResponse, error) {
	roles, err := s.userRepo.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("GetUserRoles: failed to get roles: %w", err)
	}

	result := make([]models.RoleResponse, len(roles))
	for i, role := range roles {
		result[i] = *role.ToResponse()
	}

	return result, nil
}

// GetUserPermissions gets permissions for a user
func (s *UserService) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.PermissionResponse, error) {
	permissions, err := s.userRepo.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("GetUserPermissions: failed to get permissions: %w", err)
	}

	result := make([]models.PermissionResponse, len(permissions))
	for i, perm := range permissions {
		result[i] = *perm.ToResponse()
	}

	return result, nil
}

// SetUserRoles sets the roles for a user (replaces existing roles)
func (s *UserService) SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	// C-4: fetch the user to know their tenant before verifying roles
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("SetUserRoles: failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("SetUserRoles: user not found")
	}

	// C-4: verify all roles exist AND belong to the user's tenant
	for _, roleID := range roleIDs {
		role, err := s.roleRepo.GetByIDAndTenant(ctx, roleID, user.TenantID)
		if err != nil {
			return fmt.Errorf("SetUserRoles: failed to get role %s: %w", roleID, err)
		}
		if role == nil {
			return fmt.Errorf("SetUserRoles: role %s not found in tenant", roleID)
		}
	}

	// C-4 / C-1: caller cannot assign roles with priority >= their own maximum
	if assignedBy != nil {
		callerMax, err := s.roleRepo.GetMaxPriorityForUser(ctx, *assignedBy, user.TenantID)
		if err != nil {
			return fmt.Errorf("SetUserRoles: failed to check caller priority: %w", err)
		}
		for _, roleID := range roleIDs {
			role, _ := s.roleRepo.GetByIDAndTenant(ctx, roleID, user.TenantID)
			if role != nil && role.Priority >= callerMax {
				return fmt.Errorf("SetUserRoles: cannot assign role with priority >= your highest role priority (%d)", callerMax)
			}
		}
	}

	// Get existing roles before assignment for diff
	existingRoles, err := s.userRepo.GetUserRoles(ctx, userID)
	if err != nil {
		return fmt.Errorf("SetUserRoles: failed to get existing roles: %w", err)
	}
	existingRoleIDs := make(map[uuid.UUID]bool)
	for _, r := range existingRoles {
		existingRoleIDs[r.ID] = true
	}

	// Assign roles
	if err := s.userRepo.AssignRoles(ctx, userID, roleIDs, assignedBy); err != nil {
		return fmt.Errorf("SetUserRoles: failed to assign roles: %w", err)
	}

	// Refresh user for tenant ID (already validated above, ignore error here)
	user, _ = s.userRepo.GetByID(ctx, userID)
	if user != nil {
		s.publishRoleDiffEvents(ctx, user, userID, roleIDs, existingRoles, existingRoleIDs)
		s.invalidateRoleSessionsAndPublish(ctx, user, userID)
		s.syncSpiceDBRoleMembership(ctx, user.TenantID, userID, roleIDs, existingRoles, existingRoleIDs)

		// ADR-A10 SoD (23-authorization-rbac-abac-rebac.md §5.2):
		// evaluate on every role-assignment write. Warn-mode only —
		// never blocks this write, and any evaluation failure is
		// logged internally by EvaluateUserAsync, never surfaced here.
		if s.sodService != nil {
			s.sodService.EvaluateUserAsync(ctx, user.TenantID, userID, roleIDs)
		}
	}

	// Invalidate cache when roles change
	if s.redisCache != nil {
		cacheKey := fmt.Sprintf("iam:user:%s", userID.String())
		_ = s.redisCache.Delete(ctx, cacheKey)
	}

	return nil
}

// syncSpiceDBRoleMembership writes the role diff to SpiceDB synchronously so
// authorization checks (AuthorizationEngine.CheckPermission — the sole
// runtime authority for v2 tokens) reflect the change immediately, rather
// than waiting for SpiceDBReconciler's next scheduled pass (24h in
// production). Grants stay best-effort. Removals are already durably queued
// by the repository in the role transaction and are drained after commit.
func (s *UserService) syncSpiceDBRoleMembership(
	ctx context.Context, tenantID, userID uuid.UUID,
	roleIDs []uuid.UUID, existingRoles []models.Role, existingRoleIDs map[uuid.UUID]bool,
) {
	if s.roleRevokes != nil {
		if err := s.roleRevokes.Drain(ctx, userID); err != nil {
			logger.Warn("Role revokes remain durably queued", zap.Error(err))
		}
	}
	if s.spicedbClient == nil {
		return
	}
	newRoleIDs := make(map[uuid.UUID]bool, len(roleIDs))
	for _, roleID := range roleIDs {
		newRoleIDs[roleID] = true
		if existingRoleIDs[roleID] {
			continue
		}
		s.writeRoleAssignmentFor(ctx, tenantID, userID, roleID)
		if _, err := s.spicedbClient.WriteUserRole(ctx, tenantID, userID, roleID); err != nil {
			logger.Warn("Failed to write SpiceDB role membership on SetUserRoles",
				zap.String("tenant_id", tenantID.String()),
				zap.String("user_id", userID.String()),
				zap.String("role_id", roleID.String()),
				zap.Error(err),
			)
		}
	}
	for _, existingRole := range existingRoles {
		if newRoleIDs[existingRole.ID] {
			continue
		}
		s.deleteRoleAssignmentIfLast(ctx, tenantID, userID, existingRole, newRoleIDs)
	}
}

// writeRoleAssignmentFor records role_assignment#assigned for the role's
// module (module-scoped roles only). Best effort like the surrounding sync:
// Postgres stays the system of record.
func (s *UserService) writeRoleAssignmentFor(ctx context.Context, tenantID, userID, roleID uuid.UUID) {
	w, ok := s.spicedbClient.(userServiceRoleAssignmentWriter)
	if !ok || s.roleRepo == nil {
		return
	}
	role, err := s.roleRepo.GetByIDAndTenant(ctx, roleID, tenantID)
	if err != nil || role == nil || role.Module == nil || *role.Module == "" {
		return
	}
	if err := w.WriteRoleAssignment(ctx, tenantID, userID, *role.Module); err != nil {
		logger.Warn("Failed to write SpiceDB role_assignment on SetUserRoles",
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.String("module", *role.Module),
			zap.Error(err),
		)
	}
}

// deleteRoleAssignmentIfLast removes role_assignment for the removed role's
// module when the user keeps no other role of that module.
func (s *UserService) deleteRoleAssignmentIfLast(ctx context.Context, tenantID, userID uuid.UUID, removed models.Role, remainingRoleIDs map[uuid.UUID]bool) {
	w, ok := s.spicedbClient.(userServiceRoleAssignmentWriter)
	if !ok || s.roleRepo == nil || removed.Module == nil || *removed.Module == "" {
		return
	}
	for id := range remainingRoleIDs {
		if r, err := s.roleRepo.GetByIDAndTenant(ctx, id, tenantID); err == nil && r != nil && r.Module != nil && *r.Module == *removed.Module {
			return
		}
	}
	if err := w.DeleteRoleAssignment(ctx, tenantID, userID, *removed.Module); err != nil {
		logger.Warn("Failed to delete SpiceDB role_assignment on SetUserRoles",
			zap.String("tenant_id", tenantID.String()),
			zap.String("user_id", userID.String()),
			zap.String("module", *removed.Module),
			zap.Error(err),
		)
	}
}

// publishRoleDiffEvents publishes assignment/revocation events for the role diff.
func (s *UserService) publishRoleDiffEvents(ctx context.Context, user *models.User, userID uuid.UUID, roleIDs []uuid.UUID, existingRoles []models.Role, existingRoleIDs map[uuid.UUID]bool) {
	for _, roleID := range roleIDs {
		if !existingRoleIDs[roleID] {
			s.publishUserRoleEvent(ctx, IAMEventTopics.UserRoleAssigned, user.TenantID, userID, roleID)
		}
	}
	newRoleIDs := make(map[uuid.UUID]bool, len(roleIDs))
	for _, roleID := range roleIDs {
		newRoleIDs[roleID] = true
	}
	for _, existingRole := range existingRoles {
		if !newRoleIDs[existingRole.ID] {
			s.publishUserRoleEvent(ctx, IAMEventTopics.UserRoleRevoked, user.TenantID, userID, existingRole.ID)
		}
	}
}

// invalidateRoleSessionsAndPublish increments the role version and publishes a permission invalidation message.
func (s *UserService) invalidateRoleSessionsAndPublish(ctx context.Context, user *models.User, userID uuid.UUID) {
	if s.sessionCache == nil {
		return
	}
	newVersion, err := s.sessionCache.IncrementRoleVersion(ctx, user.TenantID)
	if err != nil {
		logger.Warn("Failed to increment role version",
			zap.String("tenant_id", user.TenantID.String()),
			zap.Error(err),
		)
	}
	if err := s.sessionCache.InvalidateUserSessionsByRoleVersion(ctx, userID, newVersion); err != nil {
		logger.Warn("Failed to invalidate user sessions",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
	}
	msg := struct {
		Type      string    `json:"type"`
		TenantID  uuid.UUID `json:"tenant_id"`
		UserID    uuid.UUID `json:"user_id"`
		Timestamp time.Time `json:"timestamp"`
		Reason    string    `json:"reason"`
	}{
		Type:      "role_changed",
		TenantID:  user.TenantID,
		UserID:    userID,
		Timestamp: time.Now(),
		Reason:    "User roles updated",
	}
	if err := s.sessionCache.PublishPermissionInvalidation(ctx, msg); err != nil {
		logger.Warn("Failed to publish permission invalidation",
			zap.String("user_id", userID.String()),
			zap.Error(err),
		)
	}
}

// ForceVerifyEmail marks a user's email as verified without sending any email.
// This is an admin-only operation used to bypass the normal email verification flow.
func (s *UserService) ForceVerifyEmail(ctx context.Context, userID uuid.UUID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("ForceVerifyEmail: failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if user.IsEmailVerified {
		return nil // idempotent — already verified is not an error
	}

	user.IsEmailVerified = true
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("ForceVerifyEmail: failed to update user: %w", err)
	}

	logger.Info("Email force-verified by admin",
		zap.String("user_id", userID.String()),
		zap.String("email", user.Email),
	)

	// HCM links employees to IAM users by verified email only (xm F3).
	s.publishUserLifecycleEvent(user, "example.iam.user.updated")

	return nil
}

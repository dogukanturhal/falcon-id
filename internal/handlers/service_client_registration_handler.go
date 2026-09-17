// SPDX-License-Identifier: AGPL-3.0-or-later

package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/dogukanturhal/falcon-id/internal/repositories"
)

// serviceClientRepo is the narrow repository interface required by
// ServiceClientRegistrationHandler.
type serviceClientRepo interface {
	UpsertServiceClient(
		ctx context.Context,
		clientID string,
		clientName string,
		serviceSlug string,
		scopes []string,
		secretHash string,
	) (repositories.UpsertServiceClientResult, error)
}

// ServiceClientRegistrationHandler handles idempotent service OAuth client
// self-registration called by platform microservices on startup.
//
// POST /api/v1/internal/service-clients/register
type ServiceClientRegistrationHandler struct {
	repo    serviceClientRepo
	log     *zap.SugaredLogger
	devMode bool // when true, dev_secret may be used instead of a generated secret
}

// NewServiceClientRegistrationHandler creates the handler.
// devMode should be set to true when Environment == "development" so that
// services can supply a deterministic dev_secret for local testing.
func NewServiceClientRegistrationHandler(repo serviceClientRepo, log *zap.SugaredLogger, devMode bool) *ServiceClientRegistrationHandler {
	return &ServiceClientRegistrationHandler{
		repo:    repo,
		log:     log,
		devMode: devMode,
	}
}

// RegisterServiceClientRequest is the JSON body for the registration endpoint.
type RegisterServiceClientRequest struct {
	// ServiceSlug identifies the calling service, e.g. "crm" or "workflow-engine".
	ServiceSlug string `json:"service_slug" binding:"required"`

	// ClientID is the stable OAuth client_id string, e.g. "svc-crm".
	ClientID string `json:"client_id" binding:"required"`

	// ClientName is a human-readable display name stored in iam_oauth_clients.
	ClientName string `json:"client_name" binding:"required"`

	// Scopes lists the OAuth scopes the service is allowed to request via
	// client_credentials. Example: ["internal.read", "internal.write"].
	Scopes []string `json:"scopes" binding:"required"`

	// DevSecret may be provided only in development mode.  When present it is
	// hashed and stored as the client secret so local envs have a predictable
	// credential.  Ignored outside development.
	DevSecret string `json:"dev_secret,omitempty"`
}

// RegisterServiceClientResponse is returned after a successful upsert.
type RegisterServiceClientResponse struct {
	// ClientID echoes the oauth client_id string.
	ClientID string `json:"client_id"`

	// RowID is the UUID primary key of the iam_oauth_clients row.
	RowID uuid.UUID `json:"row_id"`

	// ClientSecret is only populated on first creation.  It is never returned
	// on subsequent calls to prevent accidental secret disclosure.
	ClientSecret string `json:"client_secret,omitempty"`

	// Created is true on first registration, false on subsequent idempotent calls.
	Created bool `json:"created"`

	// Scopes echoes the registered scopes.
	Scopes []string `json:"scopes"`
}

// Register handles POST /api/v1/internal/service-clients/register.
// It upserts the service OAuth client and returns the plaintext secret only
// on first creation.
func (h *ServiceClientRegistrationHandler) Register(c *gin.Context) {
	var req RegisterServiceClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.Scopes) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scopes must not be empty"})
		return
	}

	// Determine the plaintext secret to hash and (optionally) return.
	// We always need a hash to pass to UpsertServiceClient.  On update the
	// repo ignores the hash so we supply an empty string — the DB value is
	// preserved untouched.
	//
	// On first insert the repo stores secretHash.  We detect "first insert" via
	// the Created flag returned by the repo, but we cannot know that ahead of
	// time.  The simple approach: always generate/use the secret, hash it, pass
	// it in.  The repo only stores the hash on INSERT; ON CONFLICT it is ignored.
	plaintext, err := h.resolveSecret(req.DevSecret)
	if err != nil {
		h.log.Errorw("Failed to generate service client secret",
			"service_slug", req.ServiceSlug,
			"client_id", req.ClientID,
			"error", err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate client secret"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		h.log.Errorw("Failed to hash service client secret",
			"service_slug", req.ServiceSlug,
			"client_id", req.ClientID,
			"error", err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash client secret"})
		return
	}

	result, err := h.repo.UpsertServiceClient(
		c.Request.Context(),
		req.ClientID,
		req.ClientName,
		req.ServiceSlug,
		req.Scopes,
		string(hash),
	)
	if err != nil {
		h.log.Errorw("Service client upsert failed",
			"service_slug", req.ServiceSlug,
			"client_id", req.ClientID,
			"error", err,
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register service client"})
		return
	}

	resp := RegisterServiceClientResponse{
		ClientID: req.ClientID,
		RowID:    result.ID,
		Created:  result.Created,
		Scopes:   req.Scopes,
	}

	// Return the plaintext secret only on first creation.
	if result.Created {
		resp.ClientSecret = plaintext
		h.log.Infow("Service client created",
			"service_slug", req.ServiceSlug,
			"client_id", req.ClientID,
			"row_id", result.ID,
		)
	} else {
		h.log.Infow("Service client scopes updated (existing client)",
			"service_slug", req.ServiceSlug,
			"client_id", req.ClientID,
			"row_id", result.ID,
		)
	}

	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	c.JSON(status, resp)
}

// resolveSecret returns the plaintext secret to use for this registration.
// In dev mode, devSecret is used when provided (allows reproducible local envs).
// Otherwise a cryptographically random 32-byte base64url secret is generated.
func (h *ServiceClientRegistrationHandler) resolveSecret(devSecret string) (string, error) {
	if h.devMode && devSecret != "" {
		return devSecret, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

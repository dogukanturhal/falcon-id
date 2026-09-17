// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
)

// AuthzInput represents the input for authorization decisions
type AuthzInput struct {
	User     AuthzUser     `json:"user"`
	Resource AuthzResource `json:"resource"`
	Action   string        `json:"action"`
	Context  AuthzContext  `json:"context"`
}

// AuthzUser represents user attributes for authorization
type AuthzUser struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	Username    string         `json:"username"`
	Email       string         `json:"email"`
	Roles       []string       `json:"roles"`
	Permissions []string       `json:"permissions"`
	Groups      []string       `json:"groups"`
	Department  string         `json:"department"`
	Attributes  map[string]any `json:"attributes"`
}

// AuthzResource represents resource attributes for authorization
type AuthzResource struct {
	Type       string         `json:"type"`     // e.g., "invoice", "contact"
	ID         string         `json:"id"`       // resource ID if known
	OwnerID    string         `json:"owner_id"` // resource owner
	TenantID   string         `json:"tenant_id"`
	Attributes map[string]any `json:"attributes"`
}

// AuthzContext represents contextual information for authorization
type AuthzContext struct {
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	Timestamp   time.Time `json:"timestamp"`
	RequestPath string    `json:"request_path"`
}

// AuthzResult represents the result of an authorization decision
type AuthzResult struct {
	Allowed bool     `json:"allowed"`
	Reasons []string `json:"reasons,omitempty"`
}

// OPAService handles policy evaluation using Open Policy Agent
type OPAService struct {
	config       *config.Config
	compiler     *ast.Compiler
	store        storage.Store
	preparedEval rego.PreparedEvalQuery
	logger       *zap.Logger
	mu           sync.RWMutex
	lastReload   time.Time
}

// NewOPAService creates a new OPA service instance
func NewOPAService(cfg *config.Config) (*OPAService, error) {
	s := &OPAService{
		config: cfg,
		store:  inmem.New(),
		logger: logger.Log,
	}

	// Load policies on initialization
	if err := s.LoadPolicies(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	return s, nil
}

// LoadPolicies loads all Rego policies from the configured path
func (s *OPAService) LoadPolicies(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	policyPath := s.config.OPAPolicyPath

	// Check if policy directory exists
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		s.logger.Warn("Policy directory does not exist, using default allow-all policy",
			zap.String("path", policyPath))
		return s.loadDefaultPolicy()
	}

	// Load all .rego files from the policy directory
	modules := make(map[string]string)

	err := filepath.Walk(policyPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("LoadPolicies: Walk failed: %w", err)
		}
		if info.IsDir() || filepath.Ext(path) != ".rego" {
			return nil
		}

		content, err := os.ReadFile(path) //nolint:gosec // path is validated before use
		if err != nil {
			return fmt.Errorf("failed to read policy file %s: %w", path, err)
		}

		moduleName := filepath.Base(path)
		modules[moduleName] = string(content)
		s.logger.Debug("Loaded policy file", zap.String("file", path))
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk policy directory: %w", err)
	}

	if len(modules) == 0 {
		s.logger.Warn("No policy files found, using default allow-all policy")
		return s.loadDefaultPolicy()
	}

	// Compile policies
	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return fmt.Errorf("failed to compile policies: %w", err)
	}

	s.compiler = compiler

	// Prepare the evaluation query (convert slashes to dots for Rego path)
	decisionPath := strings.ReplaceAll(s.config.OPADecisionPath, "/", ".")
	query := fmt.Sprintf("data.%s", decisionPath)
	r := rego.New(
		rego.Query(query),
		rego.Compiler(compiler),
		rego.Store(s.store),
	)

	preparedEval, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare evaluation: %w", err)
	}

	s.preparedEval = preparedEval
	s.lastReload = time.Now()

	s.logger.Info("OPA policies loaded successfully",
		zap.Int("policy_count", len(modules)),
		zap.String("decision_path", s.config.OPADecisionPath))

	return nil
}

// loadDefaultPolicy loads a permissive default policy when no policies are found
func (s *OPAService) loadDefaultPolicy() error {
	defaultPolicy := `
package falcon.authz

default allow := false

# Super admin has all access
allow if {
    "*" in input.user.permissions
}

# Direct permission match
allow if {
    input.action in input.user.permissions
}

# Admin role has full access
allow if {
    "admin" in input.user.roles
}
`

	modules := map[string]string{
		"default.rego": defaultPolicy,
	}

	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return fmt.Errorf("failed to compile default policy: %w", err)
	}

	s.compiler = compiler

	decisionPath := strings.ReplaceAll(s.config.OPADecisionPath, "/", ".")
	query := fmt.Sprintf("data.%s", decisionPath)
	r := rego.New(
		rego.Query(query),
		rego.Compiler(compiler),
		rego.Store(s.store),
	)

	preparedEval, err := r.PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("failed to prepare default evaluation: %w", err)
	}

	s.preparedEval = preparedEval
	s.lastReload = time.Now()

	s.logger.Info("Loaded default OPA policy")
	return nil
}

// Evaluate evaluates the authorization decision for the given input
func (s *OPAService) Evaluate(ctx context.Context, input *AuthzInput) (*AuthzResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build input map
	inputMap := map[string]interface{}{
		"user":     toMap(input.User),
		"resource": toMap(input.Resource),
		"action":   input.Action,
		"context":  toMap(input.Context),
	}

	// Evaluate the policy
	results, err := s.preparedEval.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	if len(results) == 0 {
		return &AuthzResult{Allowed: false, Reasons: []string{"no policy result"}}, nil
	}

	// Extract the allow decision
	allowed := false
	if len(results) > 0 && len(results[0].Expressions) > 0 {
		if val, ok := results[0].Expressions[0].Value.(bool); ok {
			allowed = val
		}
	}

	return &AuthzResult{Allowed: allowed}, nil
}

// EvaluatePermission is a convenience method that builds AuthzInput from common parameters
func (s *OPAService) EvaluatePermission(
	ctx context.Context,
	userID uuid.UUID,
	tenantID uuid.UUID,
	username, email string,
	roles, permissions, groups []string,
	permission string,
	resourceType, resourceID, ownerID string,
	resourceAttrs map[string]any,
	ipAddress, userAgent, requestPath string,
) (*AuthzResult, error) {
	input := &AuthzInput{
		User: AuthzUser{
			ID:          userID.String(),
			TenantID:    tenantID.String(),
			Username:    username,
			Email:       email,
			Roles:       roles,
			Permissions: permissions,
			Groups:      groups,
			Attributes:  make(map[string]any),
		},
		Resource: AuthzResource{
			Type:       resourceType,
			ID:         resourceID,
			OwnerID:    ownerID,
			TenantID:   tenantID.String(),
			Attributes: resourceAttrs,
		},
		Action: permission,
		Context: AuthzContext{
			IPAddress:   ipAddress,
			UserAgent:   userAgent,
			Timestamp:   time.Now(),
			RequestPath: requestPath,
		},
	}

	return s.Evaluate(ctx, input)
}

// ReloadPolicies reloads all policies from disk
func (s *OPAService) ReloadPolicies(ctx context.Context) error {
	s.logger.Info("Reloading OPA policies")
	return s.LoadPolicies(ctx)
}

// GetLastReloadTime returns when policies were last reloaded
func (s *OPAService) GetLastReloadTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastReload
}

// IsEnabled returns whether ABAC is enabled
func (s *OPAService) IsEnabled() bool {
	return s.config.UseABAC
}

// toMap converts a struct to a map[string]interface{}
func toMap(v interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	switch val := v.(type) {
	case AuthzUser:
		result["id"] = val.ID
		result["tenant_id"] = val.TenantID
		result["username"] = val.Username
		result["email"] = val.Email
		result["roles"] = val.Roles
		result["permissions"] = val.Permissions
		result["groups"] = val.Groups
		result["department"] = val.Department
		result["attributes"] = val.Attributes
	case AuthzResource:
		result["type"] = val.Type
		result["id"] = val.ID
		result["owner_id"] = val.OwnerID
		result["tenant_id"] = val.TenantID
		result["attributes"] = val.Attributes
	case AuthzContext:
		result["ip_address"] = val.IPAddress
		result["user_agent"] = val.UserAgent
		result["timestamp"] = val.Timestamp.Format(time.RFC3339)
		result["request_path"] = val.RequestPath
	}

	return result
}

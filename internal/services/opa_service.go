// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"go.uber.org/zap"

	"github.com/dogukanturhal/falcon-id/pkg/config"
	"github.com/dogukanturhal/falcon-id/pkg/logger"
	"github.com/dogukanturhal/falcon-id/policies"
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

// Deny is one reason the deny-only PDP policy refused a request.
type Deny struct {
	Rule   string         `json:"rule"`
	Code   string         `json:"code"`
	Params map[string]any `json:"params"`
}

// Decision is the PDP policy output. It never grants on its own: callers
// combine it as `rebacAllow && len(Denies) == 0`.
type Decision struct {
	Allow       bool     `json:"allow"`
	Denies      []Deny   `json:"denies"`
	Obligations []string `json:"obligations"`
	Revision    string   `json:"revision"`
}

// pdpDecisionQuery is the single entrypoint evaluated for every decision.
const pdpDecisionQuery = "data.falcon.pdp.v1.decision"

// OPAService handles policy evaluation using Open Policy Agent. Policies
// come from the embedded set only; there is no disk loading and no
// permissive fallback.
type OPAService struct {
	config       *config.Config
	preparedEval rego.PreparedEvalQuery
	revision     string
	logger       *zap.Logger
	mu           sync.RWMutex
	lastReload   time.Time
}

// NewOPAService creates a new OPA service instance. It fails if the embedded
// policies do not compile, so a broken policy set stops boot when OPA is on.
func NewOPAService(cfg *config.Config) (*OPAService, error) {
	s := &OPAService{
		config: cfg,
		logger: logger.Log,
	}

	if err := s.LoadPolicies(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	return s, nil
}

// embeddedModules returns the embedded non-test Rego modules and their
// revision (short SHA-256 over file names and contents).
func embeddedModules(includeTests bool) (map[string]string, string, error) {
	entries, err := fs.ReadDir(policies.PDP, policies.PDPDir)
	if err != nil {
		return nil, "", fmt.Errorf("read embedded policies: %w", err)
	}

	modules := make(map[string]string)
	h := sha256.New()
	for _, e := range entries { // ReadDir is sorted by name
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".rego") {
			continue
		}
		isTest := strings.HasSuffix(name, "_test.rego")
		if isTest && !includeTests {
			continue
		}
		content, err := fs.ReadFile(policies.PDP, policies.PDPDir+"/"+name)
		if err != nil {
			return nil, "", fmt.Errorf("read embedded policy %s: %w", name, err)
		}
		modules[name] = string(content)
		if !isTest {
			h.Write([]byte(name))
			h.Write([]byte{0})
			h.Write(content)
			h.Write([]byte{0})
		}
	}
	if len(modules) == 0 {
		return nil, "", fmt.Errorf("no embedded policies found")
	}

	return modules, hex.EncodeToString(h.Sum(nil))[:12], nil
}

// LoadPolicies compiles the embedded Rego policies and prepares the decision
// query. On failure the previously prepared policy set stays active.
func (s *OPAService) LoadPolicies(ctx context.Context) error {
	modules, revision, err := embeddedModules(false)
	if err != nil {
		return err
	}

	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return fmt.Errorf("failed to compile embedded policies: %w", err)
	}

	prepared, err := rego.New(
		rego.Query(pdpDecisionQuery),
		rego.Compiler(compiler),
		rego.Store(inmem.New()),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare policy evaluation: %w", err)
	}

	s.mu.Lock()
	s.preparedEval = prepared
	s.revision = revision
	s.lastReload = time.Now()
	s.mu.Unlock()

	s.logger.Info("OPA policies loaded",
		zap.Int("policy_count", len(modules)),
		zap.String("revision", revision))
	return nil
}

// Decide evaluates the PDP decision for a v1 input document.
func (s *OPAService) Decide(ctx context.Context, input map[string]any) (*Decision, error) {
	s.mu.RLock()
	prepared, revision := s.preparedEval, s.revision
	s.mu.RUnlock()

	results, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return nil, fmt.Errorf("policy returned no decision")
	}

	raw, err := json.Marshal(results[0].Expressions[0].Value)
	if err != nil {
		return nil, fmt.Errorf("encode policy decision: %w", err)
	}
	var d Decision
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("decode policy decision: %w", err)
	}
	d.Revision = revision
	return &d, nil
}

// Evaluate evaluates the policy for the given input. Allowed means "no deny
// rule fired"; it is never a grant. Reasons carries the deny codes.
func (s *OPAService) Evaluate(ctx context.Context, input *AuthzInput) (*AuthzResult, error) {
	d, err := s.Decide(ctx, map[string]any{
		"user":     toMap(input.User),
		"resource": toMap(input.Resource),
		"action":   input.Action,
		"context":  toMap(input.Context),
	})
	if err != nil {
		return nil, err
	}

	res := &AuthzResult{Allowed: d.Allow}
	for _, dn := range d.Denies {
		res.Reasons = append(res.Reasons, dn.Code)
	}
	return res, nil
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

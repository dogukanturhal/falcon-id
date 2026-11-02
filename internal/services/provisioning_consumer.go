// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/google/uuid"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

// ── Event types ─────────────────────────────────────────────────────────────

// SubscriptionActivatedEvent represents a subscription activation from Kafka.
type SubscriptionActivatedEvent struct {
	TenantID  uuid.UUID  `json:"tenant_id"`
	ProductID *uuid.UUID `json:"product_id,omitempty"`
	PlanID    *string    `json:"plan_id,omitempty"`
}

// ParseSubscriptionActivatedEvent parses a Kafka message payload into an event.
func ParseSubscriptionActivatedEvent(data []byte) (*SubscriptionActivatedEvent, error) {
	var event SubscriptionActivatedEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("parse subscription activated event: %w", err)
	}
	if event.TenantID == uuid.Nil {
		return nil, fmt.Errorf("subscription activated event: tenant_id is required")
	}
	return &event, nil
}

// ── Interfaces ──────────────────────────────────────────────────────────────

// provisioningInstanceService is the interface for the product instance service
// used by the provisioning consumer.
type provisioningInstanceService interface {
	Provision(ctx context.Context, productID uuid.UUID, req *models.CreateProductInstanceRequest) (*models.ProductInstance, error)
}

// provisioningReconciler triggers reconciliation of product instances.
type provisioningReconciler interface {
	Reconcile(ctx context.Context, instanceID uuid.UUID) error
	// ReconcileUntilTerminal drives the saga all the way to a terminal
	// state (or ctx's deadline), for callers that need it fully ACTIVE
	// before proceeding. See ProvisioningOrchestrator.ReconcileUntilTerminal.
	ReconcileUntilTerminal(ctx context.Context, instanceID uuid.UUID) error
}

// ProductLookup resolves which product a tenant is subscribed to.
// Used when the Kafka event doesn't include product_id.
type ProductLookup interface {
	LookupProductForTenant(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, error)
}

// productSlugResolver resolves a product's Slug — falcon-id's module-namespace
// equivalent for a provisioned product (see TemplateRoleProvisioner /
// PermissionService.RegisterModule's Module field) — from its ID. Satisfied
// by *repositories.ProductRepository.GetByID.
type productSlugResolver interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Product, error)
}

// moduleGrantProvisioner materializes a module's role templates for a tenant
// once that module/product has been granted/entitled. Satisfied by
// *TemplateRoleProvisioner. See ProvisionForModuleGrant's doc comment for
// why "module" is mapped 1:1 to models.Product.Slug here.
type moduleGrantProvisioner interface {
	ProvisionForModuleGrant(ctx context.Context, tenantID uuid.UUID, module string) (int, error)
}

// ── Options ─────────────────────────────────────────────────────────────────

// ConsumerOption configures a ProvisioningConsumer.
type ConsumerOption func(*ProvisioningConsumer)

// WithProductLookup sets a product lookup for resolving product_id when absent from events.
func WithProductLookup(lookup ProductLookup) ConsumerOption {
	return func(c *ProvisioningConsumer) {
		c.productLookup = lookup
	}
}

// WithTemplateRoleProvisioner wires TemplateRoleProvisioner into the
// subscription-activated path (the product roadmap §4.1 "Role templates"):
// example.tenant.subscription.activated is falcon-id's existing closest
// analog to a "module granted" event, so this is the trigger
// ProvisionForModuleGrant runs off, rather than a bespoke new event. It is
// optional (nil by default) and best-effort — a failure here must never
// fail the product-instance provisioning it rides along with. productSlugs
// resolves the granted product's Slug (the module namespace); when omitted,
// the hook is skipped entirely (there is no way to resolve a module name).
func WithTemplateRoleProvisioner(provisioner moduleGrantProvisioner, productSlugs productSlugResolver) ConsumerOption {
	return func(c *ProvisioningConsumer) {
		c.templateProvisioner = provisioner
		c.productSlugs = productSlugs
	}
}

// ── Consumer ────────────────────────────────────────────────────────────────

// ProvisioningConsumer handles subscription lifecycle events and triggers
// product instance provisioning. It decouples the Kafka transport from the
// business logic, making it testable without Kafka dependencies.
type ProvisioningConsumer struct {
	instanceSvc         provisioningInstanceService
	orchestrator        provisioningReconciler
	productLookup       ProductLookup
	templateProvisioner moduleGrantProvisioner
	productSlugs        productSlugResolver
}

// NewProvisioningConsumer creates a new provisioning consumer.
func NewProvisioningConsumer(
	instanceSvc provisioningInstanceService,
	orchestrator provisioningReconciler,
	opts ...ConsumerOption,
) *ProvisioningConsumer {
	c := &ProvisioningConsumer{
		instanceSvc:  instanceSvc,
		orchestrator: orchestrator,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// provisionRoleTemplatesForGrant is the best-effort module-grant hook shared
// by HandleSubscriptionActivated and HandleSubscriptionActivatedSync. It
// never returns an error: role-template provisioning is additive convenience
// (tenants can still self-serve via POST /role-templates/{key}/instantiate),
// so it must not fail — or block — the product instance provisioning it
// rides along with.
func (c *ProvisioningConsumer) provisionRoleTemplatesForGrant(ctx context.Context, tenantID, productID uuid.UUID) {
	if c.templateProvisioner == nil || c.productSlugs == nil {
		return
	}
	product, err := c.productSlugs.GetByID(ctx, productID)
	if err != nil || product == nil || product.Slug == "" {
		if err != nil {
			log.Printf("[ProvisioningConsumer] resolve product slug for role templates failed (tenant=%s product=%s): %v", tenantID, productID, err)
		}
		return
	}
	if _, err := c.templateProvisioner.ProvisionForModuleGrant(ctx, tenantID, product.Slug); err != nil {
		log.Printf("[ProvisioningConsumer] role template provisioning failed (tenant=%s module=%s): %v", tenantID, product.Slug, err)
	}
}

// HandleSubscriptionActivated processes a subscription.activated event by
// creating a product instance and triggering the provisioning orchestrator.
func (c *ProvisioningConsumer) HandleSubscriptionActivated(ctx context.Context, event SubscriptionActivatedEvent) error {
	productID, err := c.resolveProductID(ctx, event)
	if err != nil {
		return fmt.Errorf("resolve product ID: %w", err)
	}

	req := &models.CreateProductInstanceRequest{
		TenantID: event.TenantID,
		PlanID:   event.PlanID,
	}

	pi, err := c.instanceSvc.Provision(ctx, productID, req)
	if err != nil {
		return fmt.Errorf("provision product instance: %w", err)
	}

	// Trigger async reconciliation.
	go func() { //nolint:gosec // goroutine must outlive request context
		if err := c.orchestrator.Reconcile(context.Background(), pi.ID); err != nil {
			log.Printf("[ProvisioningConsumer] reconcile failed for instance %s: %v", pi.ID, err)
		}
	}()

	// Best-effort role-template materialization; see provisionRoleTemplatesForGrant.
	go c.provisionRoleTemplatesForGrant(context.Background(), event.TenantID, productID) //nolint:gosec // goroutine must outlive request context

	return nil
}

// HandleSubscriptionActivatedSync is HandleSubscriptionActivated's
// synchronous counterpart: it drives the instance's provisioning saga all
// the way to a terminal state (via ReconcileUntilTerminal), bounded by ctx,
// on the caller's own goroutine, instead of firing a single Reconcile call
// into a detached background goroutine. A single Reconcile call only
// advances ONE saga step — using it here (as an earlier version of this
// method did) would return having merely kicked off provisioning, not
// completed it, which does not close the race this method exists for.
//
// It exists for callers that mint a session/JWT immediately after
// provisioning and need the instance to actually be ACTIVE (so the
// products[] JWT claim — see models.SpiceDBClaims.ProductSubscriptions —
// is populated at mint time), not merely "provisioning kicked off".
//
// The Kafka billing-webhook path (HandleSubscriptionActivated) must stay
// fire-and-forget: there is no request waiting on it, and a webhook
// handler blocking on a multi-step migrate/seed/configure saga would
// itself become the bottleneck. Self-service signup is the opposite: a
// browser is sitting on the response, so a bounded synchronous wait is
// the correct trade — see signup_post_provisioner.go's use of this
// method via a context.WithTimeout.
//
// Reconcile is documented idempotent and safe to call multiple times, so
// if ctx is cancelled or times out mid-saga, this simply returns the
// error and leaves the row in whatever intermediate state it reached —
// the orchestrator's regular background ticker (ReconcileInterval) will
// pick the instance back up and finish it, exactly as it would for the
// async path above.
func (c *ProvisioningConsumer) HandleSubscriptionActivatedSync(ctx context.Context, event SubscriptionActivatedEvent) error {
	productID, err := c.resolveProductID(ctx, event)
	if err != nil {
		return fmt.Errorf("resolve product ID: %w", err)
	}

	req := &models.CreateProductInstanceRequest{
		TenantID: event.TenantID,
		PlanID:   event.PlanID,
	}

	pi, err := c.instanceSvc.Provision(ctx, productID, req)
	if err != nil {
		return fmt.Errorf("provision product instance: %w", err)
	}

	if err := c.orchestrator.ReconcileUntilTerminal(ctx, pi.ID); err != nil {
		return fmt.Errorf("reconcile product instance to terminal state: %w", err)
	}

	// Best-effort role-template materialization; see provisionRoleTemplatesForGrant.
	c.provisionRoleTemplatesForGrant(ctx, event.TenantID, productID)

	return nil
}

// resolveProductID determines the product_id to provision.
// Priority: event.ProductID > ProductLookup > DefaultProductID (ExampleSuite).
func (c *ProvisioningConsumer) resolveProductID(ctx context.Context, event SubscriptionActivatedEvent) (uuid.UUID, error) {
	if event.ProductID != nil && *event.ProductID != uuid.Nil {
		return *event.ProductID, nil
	}

	if c.productLookup != nil {
		pid, err := c.productLookup.LookupProductForTenant(ctx, event.TenantID)
		if err != nil {
			return uuid.Nil, fmt.Errorf("product lookup: %w", err)
		}
		return pid, nil
	}

	return models.WellKnownProductExampleSuite, nil
}

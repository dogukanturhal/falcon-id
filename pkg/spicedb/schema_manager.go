// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"go.uber.org/zap"
)

const spicedbPermView = "view"

// SchemaWriter is a minimal interface for writing SpiceDB schemas.
// It is satisfied by any type that exposes WriteSchema and ReadSchema,
// including the concrete *Client through its underlying authzed client.
type SchemaWriter interface {
	WriteSchema(ctx context.Context, schema string) error
	ReadSchema(ctx context.Context) (string, error)
}

// ResourceTypeDefinition describes a resource type that a product registers
// into the shared SpiceDB schema.
type ResourceTypeDefinition struct {
	// Name is the SpiceDB definition name, e.g. "crm_contact" or "hr_employee".
	Name string
	// ProductSlug identifies the owning product, e.g. "examplesuite".
	ProductSlug string
	// Relations lists the relationship names the type exposes,
	// e.g. ["owner", "viewer", "editor"].
	// The manager always injects a "tenant" relation automatically if omitted.
	Relations []string
	// Permissions lists the permission names the type exposes,
	// e.g. ["view", "edit", "delete"].
	Permissions []string
}

// SchemaManager dynamically extends the SpiceDB schema when products register
// new resource types.  All mutations are ADDITIVE — existing definitions are
// never removed so that live relationships remain valid.
//
// SchemaManager is safe for concurrent use.  Multiple goroutines may call
// RegisterResourceType simultaneously; each call acquires the write lock for
// the in-memory map and then, while still holding the lock, applies the schema
// to SpiceDB so that no two concurrent registrations can produce an interleaved
// write.
type SchemaManager struct {
	writer     SchemaWriter
	mu         sync.RWMutex
	registered map[string]*ResourceTypeDefinition // key = resource type Name
	logger     *zap.Logger
}

// NewSchemaManager returns a ready-to-use SchemaManager backed by writer.
func NewSchemaManager(writer SchemaWriter, logger *zap.Logger) *SchemaManager {
	return &SchemaManager{
		writer:     writer,
		registered: make(map[string]*ResourceTypeDefinition),
		logger:     logger,
	}
}

// RegisterResourceType adds (or replaces) a resource type definition and then
// applies the updated schema to SpiceDB.
//
// The operation is additive: if other definitions already exist in the remote
// schema they are preserved because ApplySchema prepends each new definition
// only when it is absent from the current schema text.
//
// Returns an error if the definition is invalid or the SpiceDB write fails.
func (m *SchemaManager) RegisterResourceType(ctx context.Context, def *ResourceTypeDefinition) error {
	if def == nil {
		return fmt.Errorf("RegisterResourceType: definition must not be nil")
	}
	if def.Name == "" {
		return fmt.Errorf("RegisterResourceType: definition Name must not be empty")
	}
	if def.ProductSlug == "" {
		return fmt.Errorf("RegisterResourceType: definition ProductSlug must not be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.registered[def.Name] = def

	m.logger.Info("registered SpiceDB resource type",
		zap.String("resource_type", def.Name),
		zap.String("product_slug", def.ProductSlug),
		zap.Strings("relations", def.Relations),
		zap.Strings("permissions", def.Permissions),
	)

	// Apply updated schema while still holding the lock so concurrent
	// registrations are serialised and the remote schema is always consistent
	// with the in-memory map.
	if err := m.applySchemaLocked(ctx); err != nil {
		// Roll back the in-memory registration so the caller can retry.
		delete(m.registered, def.Name)
		return fmt.Errorf("RegisterResourceType: failed to apply schema for %q: %w", def.Name, err)
	}

	return nil
}

// GetRegisteredTypes returns a snapshot of all currently registered resource
// type definitions, sorted by Name for deterministic ordering.
func (m *SchemaManager) GetRegisteredTypes() []*ResourceTypeDefinition {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*ResourceTypeDefinition, 0, len(m.registered))
	for _, def := range m.registered {
		// Return a shallow copy so callers cannot mutate the internal map values.
		cp := *def
		out = append(out, &cp)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

// GenerateDefinition produces a ZED-compatible definition block for a single
// resource type.
//
// The generated block always includes a "tenant" relation (relation tenant: tenant)
// so that tenant-scoped permission inheritance works uniformly across all product
// resource types.
//
// Standard relation subjects:
//   - owner     -> user
//   - viewer    -> user | group#member
//   - editor    -> user | group#member
//   - (others)  -> user | group#member
//
// Standard permissions derive from relations in a predictable order:
//   - view   = viewer + editor + owner + tenant->admin
//   - edit   = editor + owner + tenant->admin
//   - delete = owner + tenant->admin
//
// When the caller supplies custom Relations and/or Permissions the generator
// falls through to a generic template that does not embed hard-coded standard
// semantics, which keeps the output correct for novel resource shapes.
func (m *SchemaManager) GenerateDefinition(def *ResourceTypeDefinition) string {
	if def == nil {
		return ""
	}

	var sb strings.Builder

	sb.WriteString("definition ")
	sb.WriteString(def.Name)
	sb.WriteString(" {\n")

	// Always emit the tenant relation for consistent tenant-admin inheritance.
	sb.WriteString("    relation tenant: tenant\n")

	// Write each caller-supplied relation with appropriate subject types.
	for _, rel := range def.Relations {
		switch rel {
		case "tenant":
			// Already written above; skip to avoid duplication.
		case "owner":
			sb.WriteString("    relation owner: user\n")
		case "viewer", "editor":
			fmt.Fprintf(&sb, "    relation %s: user | group#member\n", rel)
		default:
			fmt.Fprintf(&sb, "    relation %s: user | group#member\n", rel)
		}
	}

	// Emit permissions.
	for _, perm := range def.Permissions {
		expr := m.buildPermissionExpr(perm, def.Relations)
		fmt.Fprintf(&sb, "    permission %s = %s\n", perm, expr)
	}

	sb.WriteString("}")

	return sb.String()
}

// buildPermissionExpr constructs a ZED permission expression for a permission
// name given the available relations.
//
// Standard semantics:
//   - view   -> viewer + editor + owner + tenant->admin  (all relations that can read)
//   - edit   -> editor + owner + tenant->admin
//   - delete -> owner + tenant->admin
//
// For any other permission name the expression is the union of all supplied
// relations plus the tenant->admin fallback.
func (m *SchemaManager) buildPermissionExpr(perm string, relations []string) string {
	relSet := make(map[string]bool, len(relations))
	for _, r := range relations {
		relSet[r] = true
	}

	tenantAdmin := "tenant->admin"

	switch perm {
	case spicedbPermView:
		parts := []string{}
		for _, r := range []string{"viewer", "editor", "owner"} {
			if relSet[r] {
				parts = append(parts, r)
			}
		}
		parts = append(parts, tenantAdmin)
		return strings.Join(parts, " + ")

	case "edit":
		parts := []string{}
		for _, r := range []string{"editor", "owner"} {
			if relSet[r] {
				parts = append(parts, r)
			}
		}
		parts = append(parts, tenantAdmin)
		return strings.Join(parts, " + ")

	case "delete":
		parts := []string{}
		if relSet["owner"] {
			parts = append(parts, "owner")
		}
		parts = append(parts, tenantAdmin)
		return strings.Join(parts, " + ")

	default:
		// Generic: union all available relations plus tenant->admin.
		parts := make([]string, 0, len(relations)+1)
		for _, r := range relations {
			if r != "tenant" {
				parts = append(parts, r)
			}
		}
		parts = append(parts, tenantAdmin)
		return strings.Join(parts, " + ")
	}
}

// ApplySchema reads the current SpiceDB schema, appends new definitions for
// any registered resource types that are not yet present, and writes the
// updated schema back.
//
// This method is safe to call from outside the package (e.g. at service
// startup) to reconcile the remote schema with all in-memory registrations.
func (m *SchemaManager) ApplySchema(ctx context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.applySchemaLocked(ctx)
}

// applySchemaLocked is the internal implementation of ApplySchema.
// It MUST be called with m.mu held (either read or write lock, but typically
// write lock because we are about to mutate SpiceDB).
func (m *SchemaManager) applySchemaLocked(ctx context.Context) error {
	if len(m.registered) == 0 {
		return nil
	}

	// Read the current schema from SpiceDB.
	currentSchema, err := m.writer.ReadSchema(ctx)
	if err != nil {
		return fmt.Errorf("applySchema: failed to read current schema: %w", err)
	}

	// Build a list of definitions to append: only those whose definition block
	// is not yet present in the schema text.  We check for the presence of
	// "definition <name>" as a conservative heuristic that avoids duplicating
	// blocks for types that were registered in a previous process lifetime.
	var additions []string

	// Iterate in sorted order so the diff is deterministic and reproducible.
	names := make([]string, 0, len(m.registered))
	for name := range m.registered {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		marker := "definition " + name
		if !strings.Contains(currentSchema, marker) {
			additions = append(additions, m.GenerateDefinition(m.registered[name]))
			m.logger.Info("adding SpiceDB definition to schema",
				zap.String("resource_type", name),
			)
		} else {
			m.logger.Debug("SpiceDB definition already present, skipping",
				zap.String("resource_type", name),
			)
		}
	}

	if len(additions) == 0 {
		m.logger.Debug("SpiceDB schema is already up-to-date; no changes written")
		return nil
	}

	// Append the new definitions to the existing schema, separated by blank lines.
	updatedSchema := currentSchema
	if updatedSchema != "" && !strings.HasSuffix(updatedSchema, "\n") {
		updatedSchema += "\n"
	}
	updatedSchema += "\n" + strings.Join(additions, "\n\n")

	if err := m.writer.WriteSchema(ctx, updatedSchema); err != nil {
		return fmt.Errorf("applySchema: failed to write updated schema: %w", err)
	}

	m.logger.Info("SpiceDB schema updated",
		zap.Int("definitions_added", len(additions)),
	)

	return nil
}

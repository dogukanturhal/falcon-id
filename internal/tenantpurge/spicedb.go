// SPDX-License-Identifier: AGPL-3.0-or-later

package tenantpurge

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
)

// spicedbDeleteBatch bounds one DeleteRelationships call; SpiceDB refuses larger
// unbounded deletes, so deletions loop until the server reports completion.
const spicedbDeleteBatch = 1000

// SpiceDBCleaner removes a purged tenant's relationships from SpiceDB.
type SpiceDBCleaner interface {
	// PurgeTenant deletes every relationship that belongs to the tenant and every
	// relationship whose subject is one of userIDs (the deleted accounts). It is
	// idempotent and returns how many relationships were deleted.
	PurgeTenant(ctx context.Context, tenantID string, userIDs []string) (int64, error)
}

type authzedCleaner struct{ c *authzed.Client }

// NewSpiceDBCleaner wraps an authzed client.
func NewSpiceDBCleaner(c *authzed.Client) SpiceDBCleaner { return &authzedCleaner{c: c} }

var (
	definitionRe = regexp.MustCompile(`^definition\s+([A-Za-z0-9_/]+)\s*\{`)
	tenantRelRe  = regexp.MustCompile(`^relation\s+tenant\s*:\s*tenant\s*$`)
)

// parseSchema returns every definition name and the subset that declares
// `relation tenant: tenant`.
func parseSchema(text string) (all, tenantLinked []string) {
	cur := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if m := definitionRe.FindStringSubmatch(line); m != nil {
			cur = m[1]
			all = append(all, cur)
			continue
		}
		if cur != "" && tenantRelRe.MatchString(line) {
			tenantLinked = append(tenantLinked, cur)
		}
	}
	sort.Strings(all)
	sort.Strings(tenantLinked)
	return all, tenantLinked
}

// skipDefinition reports definitions that are never swept by prefix or subject: hxl_platform is the single
// operator-plane object shared by every tenant.
func skipDefinition(name string) bool { return name == "hxl_platform" }

func (a *authzedCleaner) PurgeTenant(ctx context.Context, tenantID string, userIDs []string) (int64, error) {
	if IsProtectedTenant(tenantID) {
		return 0, fmt.Errorf("refusing to purge spicedb relationships of protected tenant")
	}
	schema, err := a.c.ReadSchema(ctx, &v1.ReadSchemaRequest{})
	if err != nil {
		return 0, fmt.Errorf("read spicedb schema: %w", err)
	}
	all, linked := parseSchema(schema.GetSchemaText())
	if len(all) == 0 {
		return 0, fmt.Errorf("spicedb schema has no definitions, refusing to continue")
	}

	var total int64
	del := func(f *v1.RelationshipFilter) error {
		n, err := a.deleteAll(ctx, f)
		total += n
		return err
	}

	// 1. Resources linked to the tenant: delete all their relationships.
	for _, def := range linked {
		if skipDefinition(def) {
			continue
		}
		ids, err := a.linkedResourceIDs(ctx, def, tenantID)
		if err != nil {
			return total, err
		}
		for _, id := range ids {
			if err := del(&v1.RelationshipFilter{ResourceType: def, OptionalResourceId: id}); err != nil {
				return total, err
			}
		}
	}
	// 2. Resources whose id is scoped "<tenant>/<id>" (roles, groups, scoped users).
	for _, def := range all {
		if skipDefinition(def) {
			continue
		}
		if err := del(&v1.RelationshipFilter{ResourceType: def, OptionalResourceIdPrefix: tenantID + "/"}); err != nil {
			return total, err
		}
	}
	// 3. The tenant object itself, and any tuple whose subject is the tenant.
	if err := del(&v1.RelationshipFilter{ResourceType: "tenant", OptionalResourceId: tenantID}); err != nil {
		return total, err
	}
	for _, def := range all {
		if skipDefinition(def) {
			continue
		}
		f := &v1.RelationshipFilter{ResourceType: def, OptionalSubjectFilter: &v1.SubjectFilter{SubjectType: "tenant", OptionalSubjectId: tenantID}}
		if err := del(f); err != nil {
			return total, err
		}
	}
	// 4. Tuples whose subject is a deleted account by its bare id. Tenant-scoped
	// subjects ("<tenant>/<user>") only occur on resources swept above.
	for _, uid := range userIDs {
		for _, def := range all {
			if skipDefinition(def) {
				continue
			}
			f := &v1.RelationshipFilter{ResourceType: def, OptionalSubjectFilter: &v1.SubjectFilter{SubjectType: "user", OptionalSubjectId: uid}}
			if err := del(f); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// linkedResourceIDs lists the ids of def resources related to tenant:<tenantID>
// through their `tenant` relation.
func (a *authzedCleaner) linkedResourceIDs(ctx context.Context, def, tenantID string) ([]string, error) {
	stream, err := a.c.ReadRelationships(ctx, &v1.ReadRelationshipsRequest{
		Consistency: &v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		RelationshipFilter: &v1.RelationshipFilter{
			ResourceType:          def,
			OptionalRelation:      "tenant",
			OptionalSubjectFilter: &v1.SubjectFilter{SubjectType: "tenant", OptionalSubjectId: tenantID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("read %s relationships: %w", def, err)
	}
	seen := map[string]struct{}{}
	var ids []string
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read %s relationships: %w", def, err)
		}
		id := msg.GetRelationship().GetResource().GetObjectId()
		if _, ok := seen[id]; ok || id == "" {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, nil
}

// deleteAll deletes everything matching f, in bounded batches.
func (a *authzedCleaner) deleteAll(ctx context.Context, f *v1.RelationshipFilter) (int64, error) {
	var total int64
	for {
		resp, err := a.c.DeleteRelationships(ctx, &v1.DeleteRelationshipsRequest{
			RelationshipFilter:            f,
			OptionalLimit:                 spicedbDeleteBatch,
			OptionalAllowPartialDeletions: true,
		})
		if err != nil {
			return total, fmt.Errorf("delete %s relationships: %w", f.GetResourceType(), err)
		}
		total += int64(resp.GetRelationshipsDeletedCount())
		if resp.GetDeletionProgress() != v1.DeleteRelationshipsResponse_DELETION_PROGRESS_PARTIAL {
			return total, nil
		}
	}
}

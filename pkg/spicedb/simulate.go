// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"fmt"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/google/uuid"
)

// TraceNode is one step of a SpiceDB check resolution, flattened for the
// policy simulator (23-authorization-rbac-abac-rebac.md §7 authorize/simulate).
// Object ids are shown without the per-tenant scoping prefix.
type TraceNode struct {
	Resource     string      `json:"resource"`
	Permission   string      `json:"permission"`
	Result       string      `json:"result"`
	Caveat       string      `json:"caveat,omitempty"`
	CaveatResult string      `json:"caveatResult,omitempty"`
	Children     []TraceNode `json:"children,omitempty"`
}

// SimulationResult is a real SpiceDB Check plus its resolution trace.
type SimulationResult struct {
	CheckOutcome
	Trace TraceNode
	// Caveats lists every caveat evaluated on the way, with its result, so a
	// denial can name the caveat that failed.
	Caveats []CaveatEvaluation
}

// CaveatEvaluation is one caveat seen in a trace.
type CaveatEvaluation struct {
	Name   string `json:"name"`
	Result string `json:"result"`
}

// SimulatePermission runs the real SpiceDB Check for (user, objectType:objectID,
// permission) inside the tenant with tracing on. It bypasses the check cache so
// the trace is always fresh, and gets the same check-time caveat context (`now`) as every other check
// (see check_context.go). It never writes.
func (c *Client) SimulatePermission(ctx context.Context, tenantID, userID uuid.UUID, objectType, objectID, permission string) (*SimulationResult, error) {
	req := c.newCheckRequest(
		&v1.Consistency{Requirement: &v1.Consistency_FullyConsistent{FullyConsistent: true}},
		&v1.ObjectReference{ObjectType: objectType, ObjectId: c.tenantScopedID(tenantID, objectID)},
		&v1.ObjectReference{ObjectType: spicedbObjectTypeUser, ObjectId: c.tenantScopedID(tenantID, userID.String())},
		permission,
	)
	req.WithTracing = true

	var resp *v1.CheckPermissionResponse
	if err := c.runRead(ctx, func(ctx context.Context) error {
		var e error
		resp, e = c.spicedb.CheckPermission(ctx, req)
		return e
	}); err != nil {
		RecordError("simulate_permission", "grpc_error")
		return nil, fmt.Errorf("SimulatePermission: %w", err)
	}

	out := &SimulationResult{CheckOutcome: outcomeFromPermissionship(resp.Permissionship, resp.PartialCaveatInfo)}
	if resp.DebugTrace != nil && resp.DebugTrace.Check != nil {
		out.Trace = c.flattenTrace(tenantID, resp.DebugTrace.Check, &out.Caveats)
	}
	return out, nil
}

func (c *Client) flattenTrace(tenantID uuid.UUID, t *v1.CheckDebugTrace, caveats *[]CaveatEvaluation) TraceNode {
	n := TraceNode{
		Resource:   t.GetResource().GetObjectType() + ":" + c.stripTenantPrefix(tenantID, t.GetResource().GetObjectId()),
		Permission: t.GetPermission(),
		Result:     t.GetResult().String(),
	}
	if ci := t.GetCaveatEvaluationInfo(); ci != nil && ci.GetCaveatName() != "" {
		n.Caveat = ci.GetCaveatName()
		n.CaveatResult = ci.GetResult().String()
		*caveats = append(*caveats, CaveatEvaluation{Name: n.Caveat, Result: n.CaveatResult})
	}
	for _, sub := range t.GetSubProblems().GetTraces() {
		n.Children = append(n.Children, c.flattenTrace(tenantID, sub, caveats))
	}
	return n
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// authorization_engine_tracing.go — OpenTelemetry distributed tracing for authorization decisions.
//
// Wraps CheckPermission and CheckContextualPermission (EvaluatePolicy) with OTel spans
// so every authorization decision is traceable in Jaeger/Tempo/Grafana.
//
// Attributes follow the Zanzibar/SpiceDB naming convention:
//   - authz.subject     (user UUID)
//   - authz.tenant_id
//   - authz.permission  (module-level: "crm:contacts:read")
//   - authz.resource_type / authz.resource_id / authz.action (resource-level)
//   - authz.decision    ("allowed" | "denied")
//   - authz.source      ("spicedb" | "opa")
//   - authz.cache_hit   (bool)
//
// The instrumented variants are exposed as separate public methods so callers
// can opt-in without touching the core engine logic.

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
)

const authzTracerName = "falcon-id/authz"

// authzTracer returns the OTel tracer for authorization spans.
func authzTracer() trace.Tracer {
	return otel.Tracer(authzTracerName)
}

// decisionAttribute returns a consistent "allowed" or "denied" string for span attributes.
func decisionAttribute(allowed bool) string {
	if allowed {
		return "allowed"
	}
	return "denied"
}

// CheckPermissionTraced wraps CheckPermission with an OTel span.
//
// Attributes:
//   - authz.subject, authz.tenant_id, authz.permission
//   - authz.decision, authz.source, authz.cache_hit
func (e *authorizationEngine) CheckPermissionTraced(ctx context.Context, req PermissionRequest) (*PermissionResult, error) {
	ctx, span := authzTracer().Start(ctx, "AuthzEngine.CheckPermission",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("authz.subject", req.UserID.String()),
			attribute.String("authz.tenant_id", req.TenantID.String()),
			attribute.String("authz.permission", req.Permission),
			attribute.Bool("authz.has_zed_token", req.ZedToken != ""),
		),
	)
	defer span.End()

	result, err := e.CheckPermission(ctx, req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, fmt.Sprintf("permission check error: %s", err.Error()))
		return nil, err
	}

	span.SetAttributes(
		attribute.String("authz.decision", decisionAttribute(result.Allowed)),
		attribute.String("authz.source", result.Source),
		attribute.Bool("authz.cache_hit", result.CacheHit),
		attribute.String("authz.reason", result.Reason),
	)

	if !result.Allowed {
		span.SetStatus(codes.Ok, "access denied") // Not an error — expected outcome
	} else {
		span.SetStatus(codes.Ok, "access granted")
	}

	return result, nil
}

// CheckResourcePermissionTraced wraps CheckResourcePermission with an OTel span.
//
// Attributes:
//   - authz.subject, authz.tenant_id
//   - authz.resource_type, authz.resource_id, authz.action
//   - authz.decision, authz.source
func (e *authorizationEngine) CheckResourcePermissionTraced(ctx context.Context, req ResourcePermissionRequest) (*PermissionResult, error) {
	ctx, span := authzTracer().Start(ctx, "AuthzEngine.CheckResourcePermission",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("authz.subject", req.UserID.String()),
			attribute.String("authz.tenant_id", req.TenantID.String()),
			attribute.String("authz.resource_type", req.ResourceType),
			attribute.String("authz.resource_id", req.ResourceID),
			attribute.String("authz.action", req.Action),
			attribute.Bool("authz.has_zed_token", req.ZedToken != ""),
		),
	)
	defer span.End()

	result, err := e.CheckResourcePermission(ctx, req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, fmt.Sprintf("resource permission check error: %s", err.Error()))
		return nil, err
	}

	span.SetAttributes(
		attribute.String("authz.decision", decisionAttribute(result.Allowed)),
		attribute.String("authz.source", result.Source),
		attribute.String("authz.reason", result.Reason),
	)
	span.SetStatus(codes.Ok, decisionAttribute(result.Allowed))

	return result, nil
}

// EvaluatePolicyTraced wraps CheckContextualPermission with an OTel span.
// "EvaluatePolicy" maps to the concept of policy evaluation in OPA/Zanzibar.
//
// Attributes:
//   - authz.subject, authz.tenant_id
//   - authz.action, authz.resource_type, authz.resource_id
//   - authz.decision, authz.source
func (e *authorizationEngine) EvaluatePolicyTraced(ctx context.Context, req ContextualPermissionRequest) (*PermissionResult, error) {
	ctx, span := authzTracer().Start(ctx, "AuthzEngine.EvaluatePolicy",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("authz.subject", req.UserID.String()),
			attribute.String("authz.tenant_id", req.TenantID.String()),
			attribute.String("authz.action", req.Action),
			attribute.String("authz.resource_type", req.ResourceType),
			attribute.String("authz.resource_id", req.ResourceID),
		),
	)
	defer span.End()

	result, err := e.CheckContextualPermission(ctx, req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, fmt.Sprintf("policy evaluation error: %s", err.Error()))
		return nil, err
	}

	span.SetAttributes(
		attribute.String("authz.decision", decisionAttribute(result.Allowed)),
		attribute.String("authz.source", result.Source),
		attribute.String("authz.reason", result.Reason),
	)
	span.SetStatus(codes.Ok, decisionAttribute(result.Allowed))

	return result, nil
}

// BatchCheckPermissionsTraced wraps BatchCheckPermissions with an OTel span.
//
// Attributes:
//   - authz.subject, authz.tenant_id
//   - authz.batch_size
//   - authz.batch_granted_count (permissions that were allowed)
func (e *authorizationEngine) BatchCheckPermissionsTraced(ctx context.Context, userID, tenantID uuid.UUID, permissions []string) (map[string]bool, error) {
	ctx, span := authzTracer().Start(ctx, "AuthzEngine.BatchCheckPermissions",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("authz.subject", userID.String()),
			attribute.String("authz.tenant_id", tenantID.String()),
			attribute.Int("authz.batch_size", len(permissions)),
		),
	)
	defer span.End()

	results, err := e.BatchCheckPermissions(ctx, userID, tenantID, permissions)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "batch permission check failed")
		return nil, err
	}

	grantedCount := 0
	for _, allowed := range results {
		if allowed {
			grantedCount++
		}
	}

	span.SetAttributes(
		attribute.Int("authz.batch_granted_count", grantedCount),
	)
	span.SetStatus(codes.Ok, "batch check complete")

	return results, nil
}

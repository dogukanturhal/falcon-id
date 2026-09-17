// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// delegation_service_tracing.go — OpenTelemetry distributed tracing for DelegationService operations.
//
// Wraps critical DelegationService methods so that delegation creation and
// revocation are visible as spans in the distributed trace.
// Delegations are security-sensitive operations that require full audit visibility.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const delegationTracerName = "falcon-id/delegation"

func delegationTracer() trace.Tracer {
	return otel.Tracer(delegationTracerName)
}

// CreateDelegationWithTracing wraps CreateDelegation with an OTel span.
func (s *DelegationService) CreateDelegationWithTracing(ctx context.Context, delegatorID, tenantID uuid.UUID, req *models.CreateDelegationRequest) (*models.Delegation, error) {
	ctx, span := delegationTracer().Start(ctx, "DelegationService.CreateDelegation",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("delegation.delegator_id", delegatorID.String()),
			attribute.String("delegation.delegatee_id", req.DelegateeID.String()),
			attribute.String("delegation.tenant_id", tenantID.String()),
			attribute.Int("delegation.permission_count", len(req.Permissions)),
		),
	)
	defer span.End()

	delegation, err := s.CreateDelegation(ctx, delegatorID, tenantID, req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("delegation.id", delegation.ID.String()),
	)
	span.SetStatus(codes.Ok, "delegation created")
	return delegation, nil
}

// RevokeDelegationWithTracing wraps RevokeDelegation with an OTel span.
func (s *DelegationService) RevokeDelegationWithTracing(ctx context.Context, delegationID, revokerID, tenantID uuid.UUID) error {
	ctx, span := delegationTracer().Start(ctx, "DelegationService.RevokeDelegation",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("delegation.id", delegationID.String()),
			attribute.String("delegation.revoker_id", revokerID.String()),
			attribute.String("delegation.tenant_id", tenantID.String()),
		),
	)
	defer span.End()

	if err := s.RevokeDelegation(ctx, delegationID, revokerID, tenantID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "delegation revoked")
	return nil
}

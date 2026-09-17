// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// impersonation_service_tracing.go — OpenTelemetry distributed tracing for ImpersonationService operations.
//
// Wraps critical ImpersonationService methods so that impersonation start and end
// events are visible as spans in the distributed trace.
// Impersonation is a privileged operation that requires the highest level of audit
// and tracing visibility.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const impersonationTracerName = "falcon-id/impersonation"

func impersonationTracer() trace.Tracer {
	return otel.Tracer(impersonationTracerName)
}

// StartImpersonationWithTracing wraps StartImpersonation with an OTel span.
func (s *ImpersonationService) StartImpersonationWithTracing(
	ctx context.Context,
	adminUserID uuid.UUID,
	targetUserID uuid.UUID,
	reason string,
	ipAddress string,
	userAgent string,
	originalSessionID *uuid.UUID,
) (*models.ImpersonationResponse, error) {
	ctx, span := impersonationTracer().Start(ctx, "ImpersonationService.StartImpersonation",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("impersonation.admin_user_id", adminUserID.String()),
			attribute.String("impersonation.target_user_id", targetUserID.String()),
			attribute.String("impersonation.ip_address", ipAddress),
		),
	)
	defer span.End()

	resp, err := s.StartImpersonation(ctx, adminUserID, targetUserID, reason, ipAddress, userAgent, originalSessionID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("impersonation.session_id", resp.ImpersonationSessionID),
	)
	span.SetStatus(codes.Ok, "impersonation started")
	return resp, nil
}

// EndImpersonationWithTracing wraps EndImpersonation with an OTel span.
func (s *ImpersonationService) EndImpersonationWithTracing(
	ctx context.Context,
	impersonationSessionID uuid.UUID,
	adminUserID uuid.UUID,
	ipAddress string,
	userAgent string,
) error {
	ctx, span := impersonationTracer().Start(ctx, "ImpersonationService.EndImpersonation",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("impersonation.session_id", impersonationSessionID.String()),
			attribute.String("impersonation.admin_user_id", adminUserID.String()),
		),
	)
	defer span.End()

	if err := s.EndImpersonation(ctx, impersonationSessionID, adminUserID, ipAddress, userAgent); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "impersonation ended")
	return nil
}

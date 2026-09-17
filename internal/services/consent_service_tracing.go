// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// consent_service_tracing.go — OpenTelemetry distributed tracing for ConsentService operations.
//
// Wraps critical ConsentService methods so that consent granting, revocation, and
// listing are visible as spans in the distributed trace.
// Consent operations are GDPR-critical and benefit from complete audit tracing.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const consentTracerName = "falcon-id/consent"

func consentTracer() trace.Tracer {
	return otel.Tracer(consentTracerName)
}

// UpdateConsentWithTracing wraps UpdateConsent with an OTel span.
// UpdateConsent handles both grant and revoke based on the granted parameter.
func (s *ConsentService) UpdateConsentWithTracing(
	ctx context.Context,
	userID, tenantID uuid.UUID,
	consentTypeName string,
	granted bool,
	ipAddress, userAgent string,
) error {
	action := "revoke"
	if granted {
		action = "grant"
	}

	ctx, span := consentTracer().Start(ctx, "ConsentService.UpdateConsent",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("consent.user_id", userID.String()),
			attribute.String("consent.tenant_id", tenantID.String()),
			attribute.String("consent.type_name", consentTypeName),
			attribute.Bool("consent.granted", granted),
			attribute.String("consent.action", action),
		),
	)
	defer span.End()

	if err := s.UpdateConsent(ctx, userID, tenantID, consentTypeName, granted, ipAddress, userAgent); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "consent updated")
	return nil
}

// GetUserConsentsWithTracing wraps GetUserConsents with an OTel span.
func (s *ConsentService) GetUserConsentsWithTracing(ctx context.Context, userID, tenantID uuid.UUID) (*models.ConsentListResponse, error) {
	ctx, span := consentTracer().Start(ctx, "ConsentService.GetUserConsents",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("consent.user_id", userID.String()),
			attribute.String("consent.tenant_id", tenantID.String()),
		),
	)
	defer span.End()

	resp, err := s.GetUserConsents(ctx, userID, tenantID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.Int("consent.count", len(resp.Consents)),
		attribute.Bool("consent.has_pending_required", resp.HasPendingRequired),
	)
	span.SetStatus(codes.Ok, "user consents retrieved")
	return resp, nil
}

// GetConsentTypesWithTracing wraps GetConsentTypes with an OTel span.
func (s *ConsentService) GetConsentTypesWithTracing(ctx context.Context, tenantID uuid.UUID) ([]models.ConsentType, error) {
	ctx, span := consentTracer().Start(ctx, "ConsentService.GetConsentTypes",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("consent.tenant_id", tenantID.String()),
		),
	)
	defer span.End()

	types, err := s.GetConsentTypes(ctx, tenantID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.Int("consent.type_count", len(types)),
	)
	span.SetStatus(codes.Ok, "consent types retrieved")
	return types, nil
}

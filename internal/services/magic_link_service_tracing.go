// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// magic_link_service_tracing.go — OpenTelemetry distributed tracing for MagicLinkService operations.
//
// Wraps critical MagicLinkService methods so that magic link creation and
// verification are visible as spans in the distributed trace.
// Magic link flows are authentication-critical paths.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const magicLinkTracerName = "falcon-id/magic-link"

func magicLinkTracer() trace.Tracer {
	return otel.Tracer(magicLinkTracerName)
}

// RequestMagicLinkWithTracing wraps RequestMagicLink with an OTel span.
func (s *MagicLinkService) RequestMagicLinkWithTracing(ctx context.Context, tenantID uuid.UUID, email, ipAddress, userAgent string) error {
	ctx, span := magicLinkTracer().Start(ctx, "MagicLinkService.RequestMagicLink",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("magic_link.tenant_id", tenantID.String()),
			attribute.String("magic_link.ip_address", ipAddress),
			// Do not include email in span attributes — PII.
		),
	)
	defer span.End()

	if err := s.RequestMagicLink(ctx, tenantID, email, ipAddress, userAgent); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "magic link requested")
	return nil
}

// VerifyMagicLinkWithTracing wraps VerifyMagicLink with an OTel span.
func (s *MagicLinkService) VerifyMagicLinkWithTracing(ctx context.Context, token, ipAddress, userAgent string) (*models.LoginResponse, error) {
	ctx, span := magicLinkTracer().Start(ctx, "MagicLinkService.VerifyMagicLink",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("magic_link.ip_address", ipAddress),
		),
	)
	defer span.End()

	resp, err := s.VerifyMagicLink(ctx, token, ipAddress, userAgent)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if resp != nil && resp.User != nil {
		span.SetAttributes(
			attribute.String("magic_link.user_id", resp.User.ID.String()),
			attribute.String("magic_link.tenant_id", resp.User.TenantID.String()),
		)
	}
	span.SetStatus(codes.Ok, "magic link verified")
	return resp, nil
}

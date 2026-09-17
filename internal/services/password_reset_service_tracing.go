// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// password_reset_service_tracing.go — OpenTelemetry distributed tracing for PasswordResetService operations.
//
// Wraps critical PasswordResetService methods so that password reset request
// and completion are visible as spans in the distributed trace.
// Password reset flows are security-sensitive paths.
//
// Note: RequestPasswordReset intentionally avoids logging user-identifying
// information in span attributes to preserve the security guarantee that the
// response is constant-time regardless of whether the user exists.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
)

const passwordResetTracerName = "falcon-id/password-reset"

func passwordResetTracer() trace.Tracer {
	return otel.Tracer(passwordResetTracerName)
}

// RequestPasswordResetWithTracing wraps RequestPasswordReset with an OTel span.
// The email is intentionally excluded from span attributes to prevent PII leakage
// and to preserve security by not revealing whether the email exists.
func (s *PasswordResetService) RequestPasswordResetWithTracing(ctx context.Context, tenantID uuid.UUID, email string, ipAddress string) error {
	ctx, span := passwordResetTracer().Start(ctx, "PasswordResetService.RequestPasswordReset",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("password_reset.tenant_id", tenantID.String()),
			attribute.String("password_reset.ip_address", ipAddress),
		),
	)
	defer span.End()

	if err := s.RequestPasswordReset(ctx, tenantID, email, ipAddress); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "password reset requested")
	return nil
}

// ResetPasswordWithTracing wraps ResetPassword with an OTel span.
func (s *PasswordResetService) ResetPasswordWithTracing(ctx context.Context, token, newPassword, ipAddress string) error {
	ctx, span := passwordResetTracer().Start(ctx, "PasswordResetService.ResetPassword",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("password_reset.ip_address", ipAddress),
		),
	)
	defer span.End()

	if err := s.ResetPassword(ctx, token, newPassword, ipAddress); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "password reset completed")
	return nil
}

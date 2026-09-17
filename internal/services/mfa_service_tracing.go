// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// mfa_service_tracing.go — OpenTelemetry distributed tracing for MFAService operations.
//
// Wraps critical MFAService methods so that MFA enrollment, verification, and
// disabling are visible as spans in the distributed trace.
// MFA operations are security-critical paths that benefit from detailed tracing.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
)

const mfaTracerName = "falcon-id/mfa"

func mfaTracer() trace.Tracer {
	return otel.Tracer(mfaTracerName)
}

// GenerateTOTPSecretWithTracing wraps GenerateTOTPSecret with an OTel span.
// This is the enrollment initiation step for TOTP-based MFA.
func (s *MFAService) GenerateTOTPSecretWithTracing(ctx context.Context, userID uuid.UUID) (*TOTPSetupResponse, error) {
	ctx, span := mfaTracer().Start(ctx, "MFAService.GenerateTOTPSecret",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("mfa.user_id", userID.String()),
			attribute.String("mfa.method", "totp"),
		),
	)
	defer span.End()

	resp, err := s.GenerateTOTPSecret(ctx, userID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetStatus(codes.Ok, "TOTP secret generated")
	return resp, nil
}

// VerifyAndEnableTOTPWithTracing wraps VerifyAndEnableTOTP with an OTel span.
// This verifies the enrollment code and activates TOTP MFA for the user.
func (s *MFAService) VerifyAndEnableTOTPWithTracing(ctx context.Context, userID uuid.UUID, code string) ([]string, error) {
	ctx, span := mfaTracer().Start(ctx, "MFAService.VerifyAndEnableTOTP",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("mfa.user_id", userID.String()),
			attribute.String("mfa.method", "totp"),
		),
	)
	defer span.End()

	backupCodes, err := s.VerifyAndEnableTOTP(ctx, userID, code)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.Int("mfa.backup_code_count", len(backupCodes)),
	)
	span.SetStatus(codes.Ok, "TOTP MFA enabled")
	return backupCodes, nil
}

// DisableMFAWithTracing wraps DisableMFA with an OTel span.
func (s *MFAService) DisableMFAWithTracing(ctx context.Context, userID uuid.UUID, password, mfaCode string) error {
	ctx, span := mfaTracer().Start(ctx, "MFAService.DisableMFA",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("mfa.user_id", userID.String()),
		),
	)
	defer span.End()

	if err := s.DisableMFA(ctx, userID, password, mfaCode); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "MFA disabled")
	return nil
}

// VerifyTOTPCodeWithTracing wraps VerifyTOTPCode with an OTel span.
func (s *MFAService) VerifyTOTPCodeWithTracing(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	ctx, span := mfaTracer().Start(ctx, "MFAService.VerifyTOTPCode",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("mfa.user_id", userID.String()),
			attribute.String("mfa.method", "totp"),
		),
	)
	defer span.End()

	valid, err := s.VerifyTOTPCode(ctx, userID, code)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return false, err
	}

	span.SetAttributes(
		attribute.Bool("mfa.code_valid", valid),
	)
	if valid {
		span.SetStatus(codes.Ok, "TOTP code verified")
	} else {
		span.SetStatus(codes.Error, "TOTP code invalid")
	}
	return valid, nil
}

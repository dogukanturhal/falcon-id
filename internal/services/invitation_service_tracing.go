// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// invitation_service_tracing.go — OpenTelemetry distributed tracing for InvitationService operations.
//
// Wraps critical InvitationService methods so that invitation creation,
// acceptance, and token validation are visible as spans in the distributed trace.
// Invitation flows are security-sensitive and benefit from detailed tracing.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dogukanturhal/falcon-id/internal/models"
)

const invitationTracerName = "falcon-id/invitation"

func invitationTracer() trace.Tracer {
	return otel.Tracer(invitationTracerName)
}

// CreateInvitationWithTracing wraps CreateInvitation with an OTel span.
func (s *InvitationService) CreateInvitationWithTracing(ctx context.Context, req *models.CreateInvitationRequest) (*models.InvitationResponse, string, error) {
	ctx, span := invitationTracer().Start(ctx, "InvitationService.CreateInvitation",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("invitation.user_id", req.UserID.String()),
			attribute.String("invitation.tenant_id", req.TenantID.String()),
			attribute.String("invitation.type", string(req.InvitationType)),
			attribute.Bool("invitation.send_email", req.SendEmail),
		),
	)
	defer span.End()

	resp, rawToken, err := s.CreateInvitation(ctx, req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, "", err
	}

	span.SetAttributes(
		attribute.String("invitation.id", resp.ID.String()),
	)
	span.SetStatus(codes.Ok, "invitation created")
	return resp, rawToken, nil
}

// AcceptInvitationWithTracing wraps AcceptInvitation with an OTel span.
func (s *InvitationService) AcceptInvitationWithTracing(ctx context.Context, req *models.SetupAccountRequest, ipAddress, userAgent string) (*models.LoginResponse, error) {
	ctx, span := invitationTracer().Start(ctx, "InvitationService.AcceptInvitation",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("invitation.ip_address", ipAddress),
		),
	)
	defer span.End()

	resp, err := s.AcceptInvitation(ctx, req, ipAddress, userAgent)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if resp != nil && resp.User != nil {
		span.SetAttributes(
			attribute.String("invitation.accepted_by_user_id", resp.User.ID.String()),
		)
	}
	span.SetStatus(codes.Ok, "invitation accepted")
	return resp, nil
}

// ValidateTokenWithTracing wraps ValidateToken with an OTel span.
func (s *InvitationService) ValidateTokenWithTracing(ctx context.Context, rawToken string) (*models.ValidateInvitationResponse, error) {
	ctx, span := invitationTracer().Start(ctx, "InvitationService.ValidateToken",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	resp, err := s.ValidateToken(ctx, rawToken)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.Bool("invitation.valid", resp.Valid),
	)
	if !resp.Valid {
		span.SetStatus(codes.Error, resp.Error)
	} else {
		span.SetStatus(codes.Ok, "invitation token valid")
	}
	return resp, nil
}

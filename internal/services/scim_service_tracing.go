// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// scim_service_tracing.go — OpenTelemetry distributed tracing for SCIMService operations.
//
// Wraps critical SCIMService methods so that SCIM user provisioning operations
// are visible as spans in the distributed trace.
// SCIM provisioning is a directory synchronization path that benefits from tracing.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const scimTracerName = "falcon-id/scim"

func scimTracer() trace.Tracer {
	return otel.Tracer(scimTracerName)
}

// CreateUserWithTracing wraps CreateUser with an OTel span.
func (s *SCIMService) CreateUserWithTracing(ctx context.Context, tenantID uuid.UUID, scimUser *models.SCIMUser) (*models.SCIMUser, error) {
	ctx, span := scimTracer().Start(ctx, "SCIMService.CreateUser",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("scim.tenant_id", tenantID.String()),
			attribute.String("scim.username", scimUser.UserName),
			attribute.Bool("scim.active", scimUser.Active),
		),
	)
	defer span.End()

	user, err := s.CreateUser(ctx, tenantID, scimUser)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("scim.user_id", user.ID),
	)
	span.SetStatus(codes.Ok, "SCIM user created")
	return user, nil
}

// UpdateUserWithTracing wraps UpdateUser with an OTel span.
func (s *SCIMService) UpdateUserWithTracing(ctx context.Context, userID uuid.UUID, scimUser *models.SCIMUser) (*models.SCIMUser, error) {
	ctx, span := scimTracer().Start(ctx, "SCIMService.UpdateUser",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("scim.user_id", userID.String()),
			attribute.Bool("scim.active", scimUser.Active),
		),
	)
	defer span.End()

	user, err := s.UpdateUser(ctx, userID, scimUser)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetStatus(codes.Ok, "SCIM user updated")
	return user, nil
}

// DeleteUserWithTracing wraps DeleteUser with an OTel span.
func (s *SCIMService) DeleteUserWithTracing(ctx context.Context, userID uuid.UUID) error {
	ctx, span := scimTracer().Start(ctx, "SCIMService.DeleteUser",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("scim.user_id", userID.String()),
		),
	)
	defer span.End()

	if err := s.DeleteUser(ctx, userID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "SCIM user deleted")
	return nil
}

// ValidateTokenWithTracing wraps ValidateToken with an OTel span.
func (s *SCIMService) ValidateTokenWithTracing(ctx context.Context, bearerToken string) (*models.SCIMToken, error) {
	ctx, span := scimTracer().Start(ctx, "SCIMService.ValidateToken",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	token, err := s.ValidateToken(ctx, bearerToken)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("scim.token_id", token.ID.String()),
		attribute.String("scim.tenant_id", token.TenantID.String()),
	)
	span.SetStatus(codes.Ok, "SCIM token validated")
	return token, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// user_service_tracing.go — OpenTelemetry distributed tracing for UserService operations.
//
// Wraps the most critical UserService methods so that every user creation,
// lookup, update, and deletion is visible as a span in the distributed trace.
// Attributes follow OpenTelemetry semantic conventions where applicable and
// add Falcon-ID–specific attributes for user context.
//
// Usage: call the WithTracing variants from handlers or higher-level
// orchestrators that already have an active OTel context.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const userTracerName = "falcon-id/user"

func userTracer() trace.Tracer {
	return otel.Tracer(userTracerName)
}

// CreateWithTracing wraps Create with an OTel span.
func (s *UserService) CreateWithTracing(ctx context.Context, req *models.CreateUserRequest, createdBy *uuid.UUID) (*models.UserResponse, error) {
	ctx, span := userTracer().Start(ctx, "UserService.Create",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("user.tenant_id", req.TenantID.String()),
			attribute.String("user.username", req.Username),
		),
	)
	defer span.End()

	resp, err := s.Create(ctx, req, createdBy)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("user.id", resp.ID.String()),
	)
	span.SetStatus(codes.Ok, "user created")
	return resp, nil
}

// GetByIDWithTracing wraps GetByID with an OTel span.
func (s *UserService) GetByIDWithTracing(ctx context.Context, id uuid.UUID) (*models.UserResponse, error) {
	ctx, span := userTracer().Start(ctx, "UserService.GetByID",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("user.id", id.String()),
		),
	)
	defer span.End()

	resp, err := s.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("user.tenant_id", resp.TenantID.String()),
		attribute.Bool("user.is_active", resp.IsActive),
	)
	span.SetStatus(codes.Ok, "user retrieved")
	return resp, nil
}

// UpdateWithTracing wraps Update with an OTel span.
func (s *UserService) UpdateWithTracing(ctx context.Context, id uuid.UUID, req *models.UpdateUserRequest, updatedBy *uuid.UUID) (*models.UserResponse, error) {
	ctx, span := userTracer().Start(ctx, "UserService.Update",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("user.id", id.String()),
		),
	)
	defer span.End()

	resp, err := s.Update(ctx, id, req, updatedBy)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetStatus(codes.Ok, "user updated")
	return resp, nil
}

// DeleteWithTracing wraps Delete with an OTel span.
func (s *UserService) DeleteWithTracing(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	ctx, span := userTracer().Start(ctx, "UserService.Delete",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("user.id", id.String()),
		),
	)
	defer span.End()

	if err := s.Delete(ctx, id, deletedBy); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "user deleted")
	return nil
}

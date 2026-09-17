// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// role_service_tracing.go — OpenTelemetry distributed tracing for RoleService operations.
//
// Wraps the most critical RoleService methods so that every role creation,
// lookup, update, and deletion is visible as a span in the distributed trace.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const roleTracerName = "falcon-id/role"

func roleTracer() trace.Tracer {
	return otel.Tracer(roleTracerName)
}

// CreateWithTracing wraps Create with an OTel span.
func (s *RoleService) CreateWithTracing(ctx context.Context, req *models.CreateRoleRequest, createdBy *uuid.UUID) (*models.RoleResponse, error) {
	ctx, span := roleTracer().Start(ctx, "RoleService.Create",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("role.tenant_id", req.TenantID.String()),
			attribute.String("role.name", req.Name),
			attribute.Bool("role.is_default", req.IsDefault),
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
		attribute.String("role.id", resp.ID.String()),
	)
	span.SetStatus(codes.Ok, "role created")
	return resp, nil
}

// GetByIDWithTracing wraps GetByID with an OTel span.
func (s *RoleService) GetByIDWithTracing(ctx context.Context, id uuid.UUID) (*models.RoleResponse, error) {
	ctx, span := roleTracer().Start(ctx, "RoleService.GetByID",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("role.id", id.String()),
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
		attribute.String("role.name", resp.Name),
		attribute.String("role.tenant_id", resp.TenantID.String()),
		attribute.Int("role.permission_count", len(resp.Permissions)),
	)
	span.SetStatus(codes.Ok, "role retrieved")
	return resp, nil
}

// UpdateWithTracing wraps Update with an OTel span.
func (s *RoleService) UpdateWithTracing(ctx context.Context, id uuid.UUID, req *models.UpdateRoleRequest, updatedBy *uuid.UUID) (*models.RoleResponse, error) {
	ctx, span := roleTracer().Start(ctx, "RoleService.Update",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("role.id", id.String()),
		),
	)
	defer span.End()

	resp, err := s.Update(ctx, id, req, updatedBy)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetStatus(codes.Ok, "role updated")
	return resp, nil
}

// DeleteWithTracing wraps Delete with an OTel span.
func (s *RoleService) DeleteWithTracing(ctx context.Context, id uuid.UUID, deletedBy *uuid.UUID) error {
	ctx, span := roleTracer().Start(ctx, "RoleService.Delete",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("role.id", id.String()),
		),
	)
	defer span.End()

	if err := s.Delete(ctx, id, deletedBy); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "role deleted")
	return nil
}

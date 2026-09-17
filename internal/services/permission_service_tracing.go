// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// permission_service_tracing.go — OpenTelemetry distributed tracing for PermissionService operations.
//
// Wraps critical PermissionService methods so that permission registration,
// listing, and individual lookups are visible as spans in the distributed trace.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const permissionTracerName = "falcon-id/permission"

func permissionTracer() trace.Tracer {
	return otel.Tracer(permissionTracerName)
}

// RegisterModuleWithTracing wraps RegisterModule with an OTel span.
func (s *PermissionService) RegisterModuleWithTracing(ctx context.Context, req *models.RegisterModuleRequest) (*models.RegisterModuleResponse, error) {
	ctx, span := permissionTracer().Start(ctx, "PermissionService.RegisterModule",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("permission.module", req.Module),
			attribute.Int("permission.definition_count", len(req.Permissions)),
		),
	)
	defer span.End()

	resp, err := s.RegisterModule(ctx, req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.Int("permission.registered", resp.Registered),
		attribute.Int("permission.updated", resp.Updated),
	)
	span.SetStatus(codes.Ok, "module permissions registered")
	return resp, nil
}

// ListWithTracing wraps List with an OTel span.
func (s *PermissionService) ListWithTracing(ctx context.Context) (*models.PermissionListResponse, error) {
	ctx, span := permissionTracer().Start(ctx, "PermissionService.List",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	resp, err := s.List(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.Int64("permission.total", resp.Total),
	)
	span.SetStatus(codes.Ok, "permissions listed")
	return resp, nil
}

// GetByIDWithTracing wraps GetByID with an OTel span.
func (s *PermissionService) GetByIDWithTracing(ctx context.Context, id uuid.UUID) (*models.PermissionResponse, error) {
	ctx, span := permissionTracer().Start(ctx, "PermissionService.GetByID",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("permission.id", id.String()),
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
		attribute.String("permission.name", resp.Name),
		attribute.String("permission.module", resp.Module),
		attribute.String("permission.resource", resp.Resource),
		attribute.String("permission.action", resp.Action),
	)
	span.SetStatus(codes.Ok, "permission retrieved")
	return resp, nil
}

// CreateWithTracing wraps Create with an OTel span.
func (s *PermissionService) CreateWithTracing(ctx context.Context, req *models.CreatePermissionRequest, auditLog *models.PlatformAuditLog) (*models.PermissionResponse, error) {
	ctx, span := permissionTracer().Start(ctx, "PermissionService.Create",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("permission.module", req.Module),
			attribute.String("permission.resource", req.Resource),
			attribute.String("permission.action", req.Action),
		),
	)
	defer span.End()

	resp, err := s.Create(ctx, req, auditLog)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("permission.id", resp.ID.String()),
		attribute.String("permission.name", resp.Name),
	)
	span.SetStatus(codes.Ok, "permission created")
	return resp, nil
}

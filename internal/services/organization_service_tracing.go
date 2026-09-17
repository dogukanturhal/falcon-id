// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// organization_service_tracing.go — OpenTelemetry distributed tracing for OrganizationService operations.
//
// Wraps critical OrganizationService methods so that organization creation,
// retrieval, and updates are visible as spans in the distributed trace.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const organizationTracerName = "falcon-id/organization"

func organizationTracer() trace.Tracer {
	return otel.Tracer(organizationTracerName)
}

// CreateOrganizationWithTracing wraps CreateOrganization with an OTel span.
func (s *OrganizationService) CreateOrganizationWithTracing(ctx context.Context, tenantID uuid.UUID, req *models.CreateOrganizationRequest, createdBy *uuid.UUID) (*models.Organization, error) {
	ctx, span := organizationTracer().Start(ctx, "OrganizationService.CreateOrganization",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("organization.tenant_id", tenantID.String()),
			attribute.String("organization.name", req.Name),
			attribute.String("organization.type", req.OrgType),
		),
	)
	defer span.End()

	org, err := s.CreateOrganization(ctx, tenantID, req, createdBy)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("organization.id", org.ID.String()),
	)
	span.SetStatus(codes.Ok, "organization created")
	return org, nil
}

// GetOrganizationWithTracing wraps GetOrganization with an OTel span.
func (s *OrganizationService) GetOrganizationWithTracing(ctx context.Context, orgID uuid.UUID) (*models.Organization, error) {
	ctx, span := organizationTracer().Start(ctx, "OrganizationService.GetOrganization",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("organization.id", orgID.String()),
		),
	)
	defer span.End()

	org, err := s.GetOrganization(ctx, orgID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("organization.name", org.Name),
		attribute.String("organization.tenant_id", org.TenantID.String()),
		attribute.String("organization.type", org.OrgType),
	)
	span.SetStatus(codes.Ok, "organization retrieved")
	return org, nil
}

// UpdateOrganizationWithTracing wraps UpdateOrganization with an OTel span.
func (s *OrganizationService) UpdateOrganizationWithTracing(ctx context.Context, orgID uuid.UUID, req *models.UpdateOrganizationRequest) (*models.Organization, error) {
	ctx, span := organizationTracer().Start(ctx, "OrganizationService.UpdateOrganization",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("organization.id", orgID.String()),
		),
	)
	defer span.End()

	org, err := s.UpdateOrganization(ctx, orgID, req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("organization.name", org.Name),
	)
	span.SetStatus(codes.Ok, "organization updated")
	return org, nil
}

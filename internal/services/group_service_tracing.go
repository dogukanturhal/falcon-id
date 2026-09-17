// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// group_service_tracing.go — OpenTelemetry distributed tracing for GroupService operations.
//
// Wraps critical GroupService methods so that group creation, member management,
// and membership changes are visible as spans in the distributed trace.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const groupTracerName = "falcon-id/group"

func groupTracer() trace.Tracer {
	return otel.Tracer(groupTracerName)
}

// CreateGroupWithTracing wraps CreateGroup with an OTel span.
func (s *GroupService) CreateGroupWithTracing(ctx context.Context, tenantID uuid.UUID, req *models.CreateGroupRequest, createdBy *uuid.UUID) (*models.Group, error) {
	ctx, span := groupTracer().Start(ctx, "GroupService.CreateGroup",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("group.tenant_id", tenantID.String()),
			attribute.String("group.name", req.Name),
			attribute.Int("group.initial_member_count", len(req.MemberIDs)),
		),
	)
	defer span.End()

	group, err := s.CreateGroup(ctx, tenantID, req, createdBy)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("group.id", group.ID.String()),
	)
	span.SetStatus(codes.Ok, "group created")
	return group, nil
}

// AddMembersWithTracing wraps AddMembers with an OTel span.
func (s *GroupService) AddMembersWithTracing(ctx context.Context, groupID uuid.UUID, userIDs []uuid.UUID, addedBy *uuid.UUID) error {
	ctx, span := groupTracer().Start(ctx, "GroupService.AddMembers",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("group.id", groupID.String()),
			attribute.Int("group.user_count", len(userIDs)),
		),
	)
	defer span.End()

	if err := s.AddMembers(ctx, groupID, userIDs, addedBy); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "members added to group")
	return nil
}

// RemoveMembersWithTracing wraps RemoveMembers with an OTel span.
func (s *GroupService) RemoveMembersWithTracing(ctx context.Context, groupID uuid.UUID, userIDs []uuid.UUID) error {
	ctx, span := groupTracer().Start(ctx, "GroupService.RemoveMembers",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("group.id", groupID.String()),
			attribute.Int("group.user_count", len(userIDs)),
		),
	)
	defer span.End()

	if err := s.RemoveMembers(ctx, groupID, userIDs); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "members removed from group")
	return nil
}

// GetGroupWithTracing wraps GetGroup with an OTel span.
func (s *GroupService) GetGroupWithTracing(ctx context.Context, groupID uuid.UUID) (*models.Group, error) {
	ctx, span := groupTracer().Start(ctx, "GroupService.GetGroup",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("group.id", groupID.String()),
		),
	)
	defer span.End()

	group, err := s.GetGroup(ctx, groupID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("group.name", group.Name),
		attribute.String("group.tenant_id", group.TenantID.String()),
	)
	span.SetStatus(codes.Ok, "group retrieved")
	return group, nil
}

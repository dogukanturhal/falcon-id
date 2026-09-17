// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// realm_service_tracing.go — OpenTelemetry distributed tracing for RealmService operations.
//
// Wraps critical RealmService methods so that realm creation, retrieval, and
// updates are visible as spans in the distributed trace. Realm operations are
// high-value platform-level events that benefit from end-to-end tracing.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const realmTracerName = "falcon-id/realm"

func realmTracer() trace.Tracer {
	return otel.Tracer(realmTracerName)
}

// CreateWithTracing wraps Create with an OTel span.
func (s *RealmService) CreateWithTracing(ctx context.Context, req *models.CreateRealmRequest, createdBy *uuid.UUID) (*models.Realm, error) {
	ctx, span := realmTracer().Start(ctx, "RealmService.Create",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("realm.slug", req.Slug),
			attribute.String("realm.type", string(req.Type)),
			attribute.String("realm.display_name", req.DisplayName),
		),
	)
	defer span.End()

	realm, err := s.Create(ctx, req, createdBy)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("realm.id", realm.ID.String()),
	)
	span.SetStatus(codes.Ok, "realm created")
	return realm, nil
}

// GetByIDWithTracing wraps GetByID with an OTel span.
func (s *RealmService) GetByIDWithTracing(ctx context.Context, id uuid.UUID) (*models.Realm, error) {
	ctx, span := realmTracer().Start(ctx, "RealmService.GetByID",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("realm.id", id.String()),
		),
	)
	defer span.End()

	realm, err := s.GetByID(ctx, id)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("realm.slug", realm.Slug),
		attribute.String("realm.type", string(realm.Type)),
		attribute.String("realm.status", string(realm.Status)),
	)
	span.SetStatus(codes.Ok, "realm retrieved")
	return realm, nil
}

// UpdateWithTracing wraps Update with an OTel span.
func (s *RealmService) UpdateWithTracing(ctx context.Context, id uuid.UUID, req *models.UpdateRealmRequest) (*models.Realm, error) {
	ctx, span := realmTracer().Start(ctx, "RealmService.Update",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("realm.id", id.String()),
		),
	)
	defer span.End()

	realm, err := s.Update(ctx, id, req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("realm.slug", realm.Slug),
	)
	span.SetStatus(codes.Ok, "realm updated")
	return realm, nil
}

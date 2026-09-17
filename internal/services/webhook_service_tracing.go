// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// webhook_service_tracing.go — OpenTelemetry distributed tracing for WebhookService operations.
//
// Wraps critical WebhookService methods so that webhook creation, event triggering,
// and delivery testing are visible as spans in the distributed trace.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const webhookTracerName = "falcon-id/webhook"

func webhookTracer() trace.Tracer {
	return otel.Tracer(webhookTracerName)
}

// CreateWebhookWithTracing wraps CreateWebhook with an OTel span.
func (s *WebhookService) CreateWebhookWithTracing(
	ctx context.Context,
	tenantID uuid.UUID,
	req *models.CreateWebhookRequest,
	createdBy *uuid.UUID,
) (*models.WebhookCreatedResponse, error) {
	ctx, span := webhookTracer().Start(ctx, "WebhookService.CreateWebhook",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("webhook.tenant_id", tenantID.String()),
			attribute.String("webhook.url", req.URL),
			attribute.Int("webhook.event_count", len(req.Events)),
		),
	)
	defer span.End()

	resp, err := s.CreateWebhook(ctx, tenantID, req, createdBy)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("webhook.id", resp.ID.String()),
	)
	span.SetStatus(codes.Ok, "webhook created")
	return resp, nil
}

// TriggerEventWithTracing wraps TriggerEvent with an OTel span.
func (s *WebhookService) TriggerEventWithTracing(ctx context.Context, event *models.WebhookEvent) error {
	ctx, span := webhookTracer().Start(ctx, "WebhookService.TriggerEvent",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("webhook.event_type", string(event.Type)),
			attribute.String("webhook.tenant_id", event.TenantID.String()),
			attribute.String("webhook.event_id", event.ID),
		),
	)
	defer span.End()

	if err := s.TriggerEvent(ctx, event); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "webhook event triggered")
	return nil
}

// DeleteWebhookWithTracing wraps DeleteWebhook with an OTel span.
func (s *WebhookService) DeleteWebhookWithTracing(ctx context.Context, id, tenantID uuid.UUID) error {
	ctx, span := webhookTracer().Start(ctx, "WebhookService.DeleteWebhook",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("webhook.id", id.String()),
			attribute.String("webhook.tenant_id", tenantID.String()),
		),
	)
	defer span.End()

	if err := s.DeleteWebhook(ctx, id, tenantID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "webhook deleted")
	return nil
}

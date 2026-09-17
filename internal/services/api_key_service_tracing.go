// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// api_key_service_tracing.go — OpenTelemetry distributed tracing for APIKeyService operations.
//
// Wraps critical APIKeyService methods so that API key creation, validation,
// and revocation are visible as spans in the distributed trace.
// API key operations are security-sensitive and benefit from complete tracing.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const apiKeyTracerName = "falcon-id/apikey"

func apiKeyTracer() trace.Tracer {
	return otel.Tracer(apiKeyTracerName)
}

// CreateWithTracing wraps Create with an OTel span.
func (s *APIKeyService) CreateWithTracing(ctx context.Context, tenantID, userID uuid.UUID, req *models.CreateAPIKeyRequest) (*models.APIKeyCreatedResponse, error) {
	ctx, span := apiKeyTracer().Start(ctx, "APIKeyService.Create",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("apikey.tenant_id", tenantID.String()),
			attribute.String("apikey.user_id", userID.String()),
			attribute.String("apikey.name", req.Name),
			attribute.Int("apikey.scope_count", len(req.Scopes)),
		),
	)
	defer span.End()

	resp, err := s.Create(ctx, tenantID, userID, req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("apikey.id", resp.ID.String()),
		attribute.String("apikey.prefix", resp.KeyPrefix),
	)
	span.SetStatus(codes.Ok, "API key created")
	return resp, nil
}

// ValidateAPIKeyWithTracing wraps ValidateAPIKey with an OTel span.
// ValidateAPIKey checks a raw API key string and returns the associated key record.
func (s *APIKeyService) ValidateAPIKeyWithTracing(ctx context.Context, rawKey string) (*models.APIKey, error) {
	ctx, span := apiKeyTracer().Start(ctx, "APIKeyService.ValidateAPIKey",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	key, err := s.ValidateAPIKey(ctx, rawKey)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("apikey.id", key.ID.String()),
		attribute.String("apikey.tenant_id", key.TenantID.String()),
		attribute.String("apikey.prefix", key.KeyPrefix),
	)
	span.SetStatus(codes.Ok, "API key validated")
	return key, nil
}

// RevokeWithTracing wraps Revoke with an OTel span.
func (s *APIKeyService) RevokeWithTracing(ctx context.Context, tenantID, keyID uuid.UUID) error {
	ctx, span := apiKeyTracer().Start(ctx, "APIKeyService.Revoke",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("apikey.id", keyID.String()),
			attribute.String("apikey.tenant_id", tenantID.String()),
		),
	)
	defer span.End()

	if err := s.Revoke(ctx, tenantID, keyID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "API key revoked")
	return nil
}

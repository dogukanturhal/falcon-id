// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// saml_service_tracing.go — OpenTelemetry distributed tracing for SAMLService operations.
//
// Wraps critical SAMLService methods so that SAML service provider creation,
// assertion generation, and SAML response generation are visible as spans in
// the distributed trace. SAML flows are authentication-critical paths.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const samlTracerName = "falcon-id/saml"

func samlTracer() trace.Tracer {
	return otel.Tracer(samlTracerName)
}

// CreateServiceProviderWithTracing wraps CreateServiceProvider with an OTel span.
func (s *SAMLService) CreateServiceProviderWithTracing(ctx context.Context, tenantID uuid.UUID, req *models.CreateSAMLServiceProviderRequest, createdBy *uuid.UUID) (*models.SAMLServiceProvider, error) {
	ctx, span := samlTracer().Start(ctx, "SAMLService.CreateServiceProvider",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("saml.tenant_id", tenantID.String()),
			attribute.String("saml.entity_id", req.EntityID),
			attribute.String("saml.acs_url", req.ACSURL),
		),
	)
	defer span.End()

	sp, err := s.CreateServiceProvider(ctx, tenantID, req, createdBy)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("saml.sp_id", sp.ID.String()),
	)
	span.SetStatus(codes.Ok, "SAML service provider created")
	return sp, nil
}

// GenerateSAMLResponseWithTracing wraps GenerateSAMLResponse with an OTel span.
func (s *SAMLService) GenerateSAMLResponseWithTracing(
	ctx context.Context,
	sp *models.SAMLServiceProvider,
	user *models.User,
	authnRequestID string,
) (string, error) {
	ctx, span := samlTracer().Start(ctx, "SAMLService.GenerateSAMLResponse",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("saml.sp_entity_id", sp.EntityID),
			attribute.String("saml.user_id", user.ID.String()),
			attribute.String("saml.tenant_id", user.TenantID.String()),
			attribute.String("saml.authn_request_id", authnRequestID),
			attribute.Bool("saml.sign_assertions", sp.SignAssertions),
		),
	)
	defer span.End()

	response, err := s.GenerateSAMLResponse(ctx, sp, user, authnRequestID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}

	span.SetStatus(codes.Ok, "SAML response generated")
	return response, nil
}

// GenerateAssertionWithTracing wraps GenerateAssertion with an OTel span.
func (s *SAMLService) GenerateAssertionWithTracing(
	ctx context.Context,
	sp *models.SAMLServiceProvider,
	user *models.User,
	authnRequestID string,
) (*models.SAMLAssertion, error) {
	ctx, span := samlTracer().Start(ctx, "SAMLService.GenerateAssertion",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("saml.sp_entity_id", sp.EntityID),
			attribute.String("saml.user_id", user.ID.String()),
			attribute.String("saml.name_id_format", sp.NameIDFormat),
		),
	)
	defer span.End()

	assertion, err := s.GenerateAssertion(ctx, sp, user, authnRequestID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("saml.assertion_id", assertion.ID),
	)
	span.SetStatus(codes.Ok, "SAML assertion generated")
	return assertion, nil
}

// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// ip_rule_service_tracing.go — OpenTelemetry distributed tracing for IPRuleService operations.
//
// Wraps critical IPRuleService methods so that IP rule creation, evaluation, and
// deletion are visible as spans in the distributed trace.
// IP rule evaluation is on the critical authentication path and benefits from tracing.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const ipRuleTracerName = "falcon-id/ip-rule"

func ipRuleTracer() trace.Tracer {
	return otel.Tracer(ipRuleTracerName)
}

// CreateRuleWithTracing wraps CreateRule with an OTel span.
func (s *IPRuleService) CreateRuleWithTracing(ctx context.Context, tenantID, userID uuid.UUID, req *models.CreateIPRuleRequest) (*models.IPRule, error) {
	ctx, span := ipRuleTracer().Start(ctx, "IPRuleService.CreateRule",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("ip_rule.tenant_id", tenantID.String()),
			attribute.String("ip_rule.name", req.Name),
			attribute.String("ip_rule.type", req.RuleType),
			attribute.String("ip_rule.ip_pattern", req.IPPattern),
		),
	)
	defer span.End()

	rule, err := s.CreateRule(ctx, tenantID, userID, req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("ip_rule.id", rule.ID.String()),
	)
	span.SetStatus(codes.Ok, "IP rule created")
	return rule, nil
}

// CheckIPWithTracing wraps CheckIP with an OTel span.
func (s *IPRuleService) CheckIPWithTracing(ctx context.Context, tenantID uuid.UUID, ipAddress string, appliesTo models.IPRuleAppliesTo) (*models.IPCheckResult, error) {
	ctx, span := ipRuleTracer().Start(ctx, "IPRuleService.CheckIP",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("ip_rule.tenant_id", tenantID.String()),
			attribute.String("ip_rule.ip_address", ipAddress),
			attribute.String("ip_rule.applies_to", string(appliesTo)),
		),
	)
	defer span.End()

	result, err := s.CheckIP(ctx, tenantID, ipAddress, appliesTo)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.Bool("ip_rule.allowed", result.Allowed),
		attribute.String("ip_rule.matched_rule_type", result.RuleType),
	)
	if result.Allowed {
		span.SetStatus(codes.Ok, "IP allowed")
	} else {
		span.SetStatus(codes.Ok, "IP denied by rule")
	}
	return result, nil
}

// DeleteRuleWithTracing wraps DeleteRule with an OTel span.
func (s *IPRuleService) DeleteRuleWithTracing(ctx context.Context, tenantID, ruleID uuid.UUID) error {
	ctx, span := ipRuleTracer().Start(ctx, "IPRuleService.DeleteRule",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("ip_rule.id", ruleID.String()),
			attribute.String("ip_rule.tenant_id", tenantID.String()),
		),
	)
	defer span.End()

	if err := s.DeleteRule(ctx, tenantID, ruleID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "IP rule deleted")
	return nil
}

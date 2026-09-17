// SPDX-License-Identifier: AGPL-3.0-or-later

package services

// device_service_tracing.go — OpenTelemetry distributed tracing for DeviceService operations.
//
// Wraps critical DeviceService methods so that device recording, trust management,
// and deletion are visible as spans in the distributed trace.
// Device trust operations are security-sensitive and benefit from detailed tracing.

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"
	"github.com/dogukanturhal/falcon-id/internal/models"
)

const deviceTracerName = "falcon-id/device"

func deviceTracer() trace.Tracer {
	return otel.Tracer(deviceTracerName)
}

// RecordDeviceWithTracing wraps RecordDevice with an OTel span.
func (s *DeviceService) RecordDeviceWithTracing(ctx context.Context, userID uuid.UUID, userAgent, ip string, fingerprint *models.DeviceFingerprint) (*models.Device, error) {
	ctx, span := deviceTracer().Start(ctx, "DeviceService.RecordDevice",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("device.user_id", userID.String()),
			attribute.String("device.ip", ip),
		),
	)
	defer span.End()

	device, err := s.RecordDevice(ctx, userID, userAgent, ip, fingerprint)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(
		attribute.String("device.id", device.ID.String()),
	)
	span.SetStatus(codes.Ok, "device recorded")
	return device, nil
}

// TrustDeviceWithTracing wraps TrustDevice with an OTel span.
func (s *DeviceService) TrustDeviceWithTracing(ctx context.Context, userID, deviceID uuid.UUID, duration string) error {
	ctx, span := deviceTracer().Start(ctx, "DeviceService.TrustDevice",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("device.id", deviceID.String()),
			attribute.String("device.user_id", userID.String()),
			attribute.String("device.trust_duration", duration),
		),
	)
	defer span.End()

	if err := s.TrustDevice(ctx, userID, deviceID, duration); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "device trusted")
	return nil
}

// DeleteDeviceWithTracing wraps DeleteDevice with an OTel span.
func (s *DeviceService) DeleteDeviceWithTracing(ctx context.Context, userID, deviceID uuid.UUID) error {
	ctx, span := deviceTracer().Start(ctx, "DeviceService.DeleteDevice",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("device.id", deviceID.String()),
			attribute.String("device.user_id", userID.String()),
		),
	)
	defer span.End()

	if err := s.DeleteDevice(ctx, userID, deviceID); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "device deleted")
	return nil
}

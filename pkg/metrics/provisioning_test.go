// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dto "github.com/prometheus/client_model/go"
)

func getCounterValue(c prometheus.Counter) float64 {
	m := &dto.Metric{}
	_ = c.Write(m)
	return m.GetCounter().GetValue()
}

func getGaugeValue(g prometheus.Gauge) float64 {
	m := &dto.Metric{}
	_ = g.Write(m)
	return m.GetGauge().GetValue()
}

func TestProvisioningStepStarted_IncrementsCounter(t *testing.T) {
	before := getCounterValue(ProvisioningStepsTotal.WithLabelValues("creating", "examplesuite"))
	ProvisioningStepsTotal.WithLabelValues("creating", "examplesuite").Inc()
	after := getCounterValue(ProvisioningStepsTotal.WithLabelValues("creating", "examplesuite"))
	assert.Equal(t, before+1, after)
}

func TestProvisioningDuration_ObservesHistogram(_ *testing.T) {
	ProvisioningDuration.WithLabelValues("creating", "examplesuite", "success").Observe(2.5)
	// No panic = success. Histogram observations are additive.
}

func TestProvisioningFailures_IncrementsCounter(t *testing.T) {
	before := getCounterValue(ProvisioningFailures.WithLabelValues("migrating", "examplesuite", "timeout"))
	ProvisioningFailures.WithLabelValues("migrating", "examplesuite", "timeout").Inc()
	after := getCounterValue(ProvisioningFailures.WithLabelValues("migrating", "examplesuite", "timeout"))
	assert.Equal(t, before+1, after)
}

func TestProvisioningActiveGauge_TracksInFlight(t *testing.T) {
	ProvisioningActive.WithLabelValues("creating").Inc()
	val := getGaugeValue(ProvisioningActive.WithLabelValues("creating"))
	assert.GreaterOrEqual(t, val, float64(1))
	ProvisioningActive.WithLabelValues("creating").Dec()
}

func TestProvisioningRetries_IncrementsCounter(t *testing.T) {
	before := getCounterValue(ProvisioningRetries.WithLabelValues("examplesuite"))
	ProvisioningRetries.WithLabelValues("examplesuite").Inc()
	after := getCounterValue(ProvisioningRetries.WithLabelValues("examplesuite"))
	assert.Equal(t, before+1, after)
}

func TestProvisioningDatabaseCount_ObservesHistogram(_ *testing.T) {
	ProvisioningDatabaseCount.WithLabelValues("examplesuite").Observe(23)
	// No panic = success.
}

func TestRecordProvisioningStep_Helper(t *testing.T) {
	// RecordProvisioningStep is a convenience function that records
	// duration and step counter in one call.
	timer := NewProvisioningTimer("seeding", "examplesuite")
	require.NotNil(t, timer)

	// Simulate work.
	time.Sleep(5 * time.Millisecond)

	// Complete successfully.
	timer.ObserveSuccess()
}

func TestRecordProvisioningStep_Failure(t *testing.T) {
	timer := NewProvisioningTimer("migrating", "hotel-pms")
	require.NotNil(t, timer)

	time.Sleep(5 * time.Millisecond)

	timer.ObserveFailure("schema_conflict")
}

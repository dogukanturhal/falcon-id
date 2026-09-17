// SPDX-License-Identifier: AGPL-3.0-or-later

package retention

import "time"

// DefaultPolicies returns standard retention policies for ExampleSuite services.
// These policies cover common data that should be cleaned up periodically.
func DefaultPolicies() []Policy {
	return []Policy{
		{
			Name:            "expired_sessions",
			Table:           "sessions",
			TimestampColumn: "expires_at",
			RetentionPeriod: 0, // Delete where expires_at < NOW()
			BatchSize:       1000,
		},
		{
			Name:            "old_audit_logs",
			Table:           "audit_logs",
			TimestampColumn: "created_at",
			RetentionPeriod: 90 * 24 * time.Hour, // 90 days
			BatchSize:       500,
		},
		{
			Name:            "expired_tokens",
			Table:           "tokens",
			TimestampColumn: "expires_at",
			RetentionPeriod: 0, // Delete where expires_at < NOW()
			BatchSize:       1000,
		},
		{
			Name:            "old_rate_limit_events",
			Table:           "rate_limit_events",
			TimestampColumn: "created_at",
			RetentionPeriod: 7 * 24 * time.Hour, // 7 days
			BatchSize:       2000,
		},
		{
			Name:                "orphaned_magic_links",
			Table:               "magic_links",
			TimestampColumn:     "expires_at",
			RetentionPeriod:     0,
			AdditionalCondition: "used = false",
			BatchSize:           500,
		},
	}
}

// IAMPolicies returns retention policies specific to the IAM service.
// These policies match the IAM database schema with iam_ table prefix.
func IAMPolicies() []Policy {
	return []Policy{
		{
			Name:                "expired_iam_sessions",
			Table:               "iam_sessions",
			TimestampColumn:     "expires_at",
			RetentionPeriod:     7 * 24 * time.Hour,  // Keep expired sessions for 7 days for audit/login history
			AdditionalCondition: "is_active = false", // Only delete soft-deleted sessions
			BatchSize:           5000,
		},
		// Phase 3 (migration 233 — commit 7e77318) DROPPED iam_refresh_tokens.
		// The OAuth refresh path now uses iam_oauth_refresh_tokens; the legacy
		// /api/v1/auth/refresh endpoint + its table are gone. Keeping a
		// retention entry against a non-existent table fires
		// `ERROR: relation "iam_refresh_tokens" does not exist` every retention
		// tick (~60-90s) and was observed to flip the shared pgx pool
		// connection into a bad state long enough to make sibling reads
		// (e.g. POST /api/v1/auth/discover) return 500 with sub-5ms latency.
		// Diagnosed live 2026-05-20 from postgres logs (291 such errors in 8h
		// against falcon-id-pg primary). The post-Phase-3 oauth refresh table
		// has its own cleanup path — no replacement entry needed here.
		{
			Name:                "expired_iam_password_resets",
			Table:               "iam_password_resets",
			TimestampColumn:     "expires_at",
			RetentionPeriod:     0,
			AdditionalCondition: "used_at IS NULL",
			BatchSize:           1000,
		},
		{
			Name:                "expired_iam_magic_links",
			Table:               "iam_magic_links",
			TimestampColumn:     "expires_at",
			RetentionPeriod:     0,
			AdditionalCondition: "used_at IS NULL",
			BatchSize:           1000,
		},
		{
			Name:            "old_iam_audit_logs",
			Table:           "iam_audit_logs",
			TimestampColumn: "created_at",
			RetentionPeriod: 90 * 24 * time.Hour, // 90 days
			BatchSize:       1000,
		},
	}
}

// BillingPolicies returns retention policies for the billing service.
func BillingPolicies() []Policy {
	return []Policy{
		{
			Name:                "old_payment_attempts",
			Table:               "payment_attempts",
			TimestampColumn:     "created_at",
			RetentionPeriod:     90 * 24 * time.Hour, // 90 days for failed attempts
			AdditionalCondition: "status IN ('failed', 'cancelled')",
			BatchSize:           500,
		},
		{
			Name:                "expired_payment_methods",
			Table:               "payment_methods",
			TimestampColumn:     "expires_at",
			RetentionPeriod:     30 * 24 * time.Hour, // 30 days after expiration
			AdditionalCondition: "status = 'expired'",
			BatchSize:           200,
		},
		{
			Name:            "old_webhook_deliveries",
			Table:           "webhook_deliveries",
			TimestampColumn: "created_at",
			RetentionPeriod: 30 * 24 * time.Hour, // 30 days
			BatchSize:       1000,
		},
	}
}

// HelpdeskPolicies returns retention policies for the helpdesk service.
func HelpdeskPolicies() []Policy {
	return []Policy{
		{
			Name:                "old_closed_tickets",
			Table:               "tickets",
			TimestampColumn:     "closed_at",
			RetentionPeriod:     365 * 24 * time.Hour, // 1 year after closing
			AdditionalCondition: "status = 'closed'",
			BatchSize:           200,
		},
		{
			Name:            "old_ticket_activities",
			Table:           "ticket_activities",
			TimestampColumn: "created_at",
			RetentionPeriod: 180 * 24 * time.Hour, // 6 months
			BatchSize:       500,
		},
	}
}

// WorkflowPolicies returns retention policies for the workflow engine service.
func WorkflowPolicies() []Policy {
	return []Policy{
		{
			Name:                "completed_workflow_instances",
			Table:               "workflow_instances",
			TimestampColumn:     "completed_at",
			RetentionPeriod:     90 * 24 * time.Hour, // 90 days after completion
			AdditionalCondition: "status IN ('completed', 'cancelled', 'failed')",
			BatchSize:           200,
		},
		{
			Name:            "old_workflow_events",
			Table:           "workflow_events",
			TimestampColumn: "created_at",
			RetentionPeriod: 30 * 24 * time.Hour, // 30 days
			BatchSize:       1000,
		},
		{
			Name:                "expired_workflow_tasks",
			Table:               "workflow_tasks",
			TimestampColumn:     "expires_at",
			RetentionPeriod:     7 * 24 * time.Hour, // 7 days after expiration
			AdditionalCondition: "status IN ('expired', 'cancelled')",
			BatchSize:           500,
		},
	}
}

// DocumentProcessorPolicies returns retention policies for the document processor service.
func DocumentProcessorPolicies() []Policy {
	return []Policy{
		{
			Name:                "temporary_documents",
			Table:               "documents",
			TimestampColumn:     "created_at",
			RetentionPeriod:     7 * 24 * time.Hour, // 7 days
			AdditionalCondition: "is_temporary = true",
			BatchSize:           100,
		},
		{
			Name:                "failed_processing_jobs",
			Table:               "processing_jobs",
			TimestampColumn:     "created_at",
			RetentionPeriod:     30 * 24 * time.Hour, // 30 days
			AdditionalCondition: "status = 'failed'",
			BatchSize:           200,
		},
		{
			Name:                "completed_processing_jobs",
			Table:               "processing_jobs",
			TimestampColumn:     "completed_at",
			RetentionPeriod:     90 * 24 * time.Hour, // 90 days
			AdditionalCondition: "status = 'completed'",
			BatchSize:           500,
		},
	}
}

// QuotaPolicies returns retention policies for the quota service.
func QuotaPolicies() []Policy {
	return []Policy{
		{
			Name:            "old_quota_usage_records",
			Table:           "quota_usage",
			TimestampColumn: "created_at",
			RetentionPeriod: 30 * 24 * time.Hour, // 30 days
			BatchSize:       2000,
		},
		{
			Name:            "expired_quota_overrides",
			Table:           "quota_overrides",
			TimestampColumn: "expires_at",
			RetentionPeriod: 0,
			BatchSize:       100,
		},
	}
}

// RealtimePolicies returns retention policies for the realtime service.
func RealtimePolicies() []Policy {
	return []Policy{
		{
			Name:            "old_presence_records",
			Table:           "presence",
			TimestampColumn: "last_seen_at",
			RetentionPeriod: 24 * time.Hour, // 24 hours of inactivity
			BatchSize:       1000,
		},
		{
			Name:            "expired_realtime_sessions",
			Table:           "realtime_sessions",
			TimestampColumn: "expires_at",
			RetentionPeriod: 0,
			BatchSize:       500,
		},
		{
			Name:            "old_message_history",
			Table:           "messages",
			TimestampColumn: "created_at",
			RetentionPeriod: 30 * 24 * time.Hour, // 30 days
			BatchSize:       2000,
		},
	}
}

// IntegrationHubPolicies returns retention policies for the integration hub service.
func IntegrationHubPolicies() []Policy {
	return []Policy{
		{
			Name:            "old_integration_logs",
			Table:           "integration_logs",
			TimestampColumn: "created_at",
			RetentionPeriod: 30 * 24 * time.Hour, // 30 days
			BatchSize:       1000,
		},
		{
			Name:                "failed_sync_attempts",
			Table:               "sync_attempts",
			TimestampColumn:     "created_at",
			RetentionPeriod:     14 * 24 * time.Hour, // 14 days
			AdditionalCondition: "status = 'failed'",
			BatchSize:           500,
		},
		{
			Name:            "expired_oauth_tokens",
			Table:           "oauth_tokens",
			TimestampColumn: "expires_at",
			RetentionPeriod: 0,
			BatchSize:       200,
		},
	}
}

// CombinePolicies merges multiple policy slices into one, ensuring no duplicates by name.
func CombinePolicies(policySets ...[]Policy) []Policy {
	seen := make(map[string]bool)
	result := []Policy{}

	for _, policySet := range policySets {
		for _, policy := range policySet {
			if !seen[policy.Name] {
				seen[policy.Name] = true
				result = append(result, policy)
			}
		}
	}

	return result
}

// SPDX-License-Identifier: AGPL-3.0-or-later

// Package testsupport contains schema fixtures shared by PostgreSQL integration tests.
package testsupport

// PermissionOutboxDDL mirrors the existing Keystone-owned permission outbox.
const PermissionOutboxDDL = `CREATE TABLE iam_permission_outbox (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
 event_type varchar NOT NULL, resource_type varchar NOT NULL, resource_id varchar NOT NULL,
 relation varchar NOT NULL, subject_type varchar NOT NULL, subject_id varchar NOT NULL,
 operation varchar NOT NULL, payload jsonb, status varchar NOT NULL DEFAULT 'pending',
 retry_count integer NOT NULL DEFAULT 0, max_retries integer NOT NULL DEFAULT 5,
 error_message text, created_at timestamptz NOT NULL DEFAULT now(), processed_at timestamptz,
 next_retry_at timestamptz);
 CREATE INDEX idx_iam_permission_outbox_status_retry ON iam_permission_outbox (status, next_retry_at)
 WHERE status IN ('pending', 'failed');`

SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

-- R-HR WP-21 employee self-service (ESS): a fourth seat class, 'employee', for an HR employee's own
-- login. Like 'external' and 'service' it never consumes a seat; unlike 'external' the user lives in
-- the tenant itself (iam_users.tenant_id = the employer) and its access ends at access_expires_at
-- (employee's last working day + the HR window, or an HR revoke), enforced by falcon-id's
-- EmployeeAccessExpiryWorker. Employee seats are provisioned only by the S2S endpoint
-- POST /internal/v1/tenants/:id/employee-accounts (business HR); team invitations cannot create them,
-- so iam_team_invitations' seat_class CHECK stays unchanged.
--
-- Purely additive and idempotent: the CHECK is swapped for its widened form (every existing row
-- already satisfies it), the column is nullable, the index is partial.
ALTER TABLE iam_user_memberships DROP CONSTRAINT IF EXISTS iam_user_memberships_seat_class_check;
ALTER TABLE iam_user_memberships ADD CONSTRAINT iam_user_memberships_seat_class_check
    CHECK (seat_class IN ('member', 'external', 'service', 'employee'));

ALTER TABLE iam_user_memberships ADD COLUMN IF NOT EXISTS access_expires_at TIMESTAMPTZ NULL;
COMMENT ON COLUMN iam_user_memberships.access_expires_at IS 'Employee-class seats only: access ends at this instant (EmployeeAccessExpiryWorker deactivates the user + membership). NULL = no expiry set.';

CREATE INDEX IF NOT EXISTS idx_iam_user_memberships_employee_expiry
    ON iam_user_memberships (tenant_id, access_expires_at)
    WHERE status = 'active' AND seat_class = 'employee' AND access_expires_at IS NOT NULL;

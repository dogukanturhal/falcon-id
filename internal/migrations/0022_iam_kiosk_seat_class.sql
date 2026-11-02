SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';

-- R6 WP-23 / D16 shop-floor kiosk: fifth seat class, 'kiosk', for a Production (PP/SCM) Operatör login. Like 'external',
-- 'service' and 'employee' it never consumes a paid seat (tenant_seat_counters / iam_users billing count); instead it is
-- counted against the quota-service resource 'kiosk_users' (1 / 3 / unlimited per production plan). Kiosk users live in the
-- tenant itself and are created only by POST /api/v1/tenants/me/kiosk-users; team invitations cannot create them, so
-- iam_team_invitations' seat_class CHECK stays unchanged.
--
-- Purely additive and idempotent: the CHECK is swapped for its widened form (every existing row already satisfies it).
-- Prerequisite guard: 0021 (v0.232.274) also re-adds this CHECK, with four values. Running 0022 first and 0021 after
-- would narrow the CHECK again, so 0022 refuses to run until 0021 has been applied (access_expires_at is its marker).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = current_schema() AND table_name = 'iam_user_memberships' AND column_name = 'access_expires_at') THEN
        RAISE EXCEPTION 'falcon-id 0022 kiosk seat class requires 0021 (v0.232.274 employee seat class) to be applied first';
    END IF;
END $$;

ALTER TABLE iam_user_memberships DROP CONSTRAINT IF EXISTS iam_user_memberships_seat_class_check;
ALTER TABLE iam_user_memberships ADD CONSTRAINT iam_user_memberships_seat_class_check
    CHECK (seat_class IN ('member', 'external', 'service', 'employee', 'kiosk'));

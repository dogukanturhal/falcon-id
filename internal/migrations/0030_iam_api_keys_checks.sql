SET LOCAL statement_timeout = '60s';
SET LOCAL lock_timeout = '5s';

-- WO#20 follow-up: 0029 declared its value CHECKs inline on
-- ADD COLUMN IF NOT EXISTS. Where the columns already existed (the
-- SchemaDefinition can create declared columns before the bundle runs),
-- the whole ADD COLUMN was skipped and the CHECKs never landed. Add them
-- as named constraints, idempotently, so every database converges.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.iam_api_keys'::regclass AND conname = 'iam_api_keys_kind_check') THEN
        ALTER TABLE public.iam_api_keys ADD CONSTRAINT iam_api_keys_kind_check
            CHECK (kind IN ('legacy', 'tenant')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.iam_api_keys'::regclass AND conname = 'iam_api_keys_hash_alg_check') THEN
        ALTER TABLE public.iam_api_keys ADD CONSTRAINT iam_api_keys_hash_alg_check
            CHECK (hash_alg = 'argon2' OR hash_alg ~ '^hmac-sha256:v[0-9]+$') NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.iam_api_keys'::regclass AND conname = 'iam_api_keys_access_check') THEN
        ALTER TABLE public.iam_api_keys ADD CONSTRAINT iam_api_keys_access_check
            CHECK (access IS NULL OR access IN ('read', 'write')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.iam_api_keys'::regclass AND conname = 'iam_api_keys_company_sync_state_check') THEN
        ALTER TABLE public.iam_api_keys ADD CONSTRAINT iam_api_keys_company_sync_state_check
            CHECK (company_sync_state IN ('synced', 'pending_add', 'pending_remove', 'failed')) NOT VALID;
    END IF;
END
$$;

ALTER TABLE public.iam_api_keys VALIDATE CONSTRAINT iam_api_keys_kind_check;
ALTER TABLE public.iam_api_keys VALIDATE CONSTRAINT iam_api_keys_hash_alg_check;
ALTER TABLE public.iam_api_keys VALIDATE CONSTRAINT iam_api_keys_access_check;
ALTER TABLE public.iam_api_keys VALIDATE CONSTRAINT iam_api_keys_company_sync_state_check;

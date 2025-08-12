-- Remove check constraint
ALTER TABLE refresh_tokens 
DROP CONSTRAINT IF EXISTS chk_refresh_tokens_revoke_reason;

-- Remove index on revoke_reason
DROP INDEX IF EXISTS idx_refresh_tokens_revoke_reason;

-- Remove revoke_reason column from refresh_tokens table
ALTER TABLE refresh_tokens 
DROP COLUMN IF EXISTS revoke_reason;
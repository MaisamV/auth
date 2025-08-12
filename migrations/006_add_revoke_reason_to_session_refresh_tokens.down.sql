-- Remove check constraint
ALTER TABLE session_refresh_tokens 
DROP CONSTRAINT IF EXISTS chk_session_refresh_tokens_revoke_reason;

-- Remove index on revoke_reason
DROP INDEX IF EXISTS idx_session_refresh_tokens_revoke_reason;

-- Remove revoke_reason column from session_refresh_tokens table
ALTER TABLE session_refresh_tokens 
DROP COLUMN IF EXISTS revoke_reason;
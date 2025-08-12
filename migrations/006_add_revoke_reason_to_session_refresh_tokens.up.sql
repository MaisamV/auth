-- Add revoke_reason column to session_refresh_tokens table
ALTER TABLE session_refresh_tokens 
ADD COLUMN revoke_reason VARCHAR(20);

-- Create index on revoke_reason for filtering
CREATE INDEX IF NOT EXISTS idx_session_refresh_tokens_revoke_reason 
ON session_refresh_tokens(revoke_reason);

-- Add check constraint to ensure valid revoke reasons
ALTER TABLE session_refresh_tokens 
ADD CONSTRAINT chk_session_refresh_tokens_revoke_reason 
CHECK (revoke_reason IN ('REFRESH', 'LOGOUT', 'PASS_CHANGE', 'SUSPECT', 'ADMIN') OR revoke_reason IS NULL);
-- Add revoke_reason column to refresh_tokens table
ALTER TABLE refresh_tokens 
ADD COLUMN revoke_reason VARCHAR(20);

-- Create index on revoke_reason for filtering
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoke_reason 
ON refresh_tokens(revoke_reason);

-- Add check constraint to ensure valid revoke reasons
ALTER TABLE refresh_tokens 
ADD CONSTRAINT chk_refresh_tokens_revoke_reason 
CHECK (revoke_reason IN ('REFRESH', 'LOGOUT', 'PASS_CHANGE', 'SUSPECT', 'ADMIN') OR revoke_reason IS NULL);
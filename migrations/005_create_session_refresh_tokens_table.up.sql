-- Create session_refresh_tokens table
CREATE TABLE IF NOT EXISTS session_refresh_tokens (
    id VARCHAR(32) PRIMARY KEY,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(32) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    revoked BOOLEAN DEFAULT FALSE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create index on user_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_session_refresh_tokens_user_id ON session_refresh_tokens(user_id);

-- Create index on expires_at for cleanup
CREATE INDEX IF NOT EXISTS idx_session_refresh_tokens_expires_at ON session_refresh_tokens(expires_at);

-- Create index on revoked for filtering
CREATE INDEX IF NOT EXISTS idx_session_refresh_tokens_revoked ON session_refresh_tokens(revoked);

-- Create composite index for active tokens by user
CREATE INDEX IF NOT EXISTS idx_session_refresh_tokens_user_active ON session_refresh_tokens(user_id, revoked, expires_at);

-- Create index on token_hash for fast token lookups
CREATE INDEX IF NOT EXISTS idx_session_refresh_tokens_token_hash ON session_refresh_tokens(token_hash);
-- Create refresh_tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(32) NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    revoked BOOLEAN DEFAULT FALSE,
    
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create index on client_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_id ON refresh_tokens(client_id);

-- Create index on user_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);

-- Create index on expires_at for cleanup
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Create index on revoked for filtering
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked ON refresh_tokens(revoked);

-- Create composite index for active tokens by user
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_active ON refresh_tokens(user_id, revoked, expires_at);
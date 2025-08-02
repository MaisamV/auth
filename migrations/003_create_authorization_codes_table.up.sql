-- Create authorization_codes table
CREATE TABLE IF NOT EXISTS authorization_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(32) NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10),
    scopes TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used BOOLEAN DEFAULT FALSE,
    
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create index on client_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_authorization_codes_client_id ON authorization_codes(client_id);

-- Create index on user_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_authorization_codes_user_id ON authorization_codes(user_id);

-- Create index on expires_at for cleanup
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);

-- Create index on used for filtering
CREATE INDEX IF NOT EXISTS idx_authorization_codes_used ON authorization_codes(used);
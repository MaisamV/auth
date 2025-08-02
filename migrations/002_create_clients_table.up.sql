-- Create clients table
CREATE TABLE IF NOT EXISTS clients (
    id VARCHAR(255) PRIMARY KEY,
    secret VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL CHECK (type IN ('public', 'confidential')),
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    grant_types TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index on type for filtering
CREATE INDEX IF NOT EXISTS idx_clients_type ON clients(type);

-- Create index on created_at for sorting
CREATE INDEX IF NOT EXISTS idx_clients_created_at ON clients(created_at);
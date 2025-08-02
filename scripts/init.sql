-- Initialize the database with sample data

-- Insert a sample OAuth client for testing
INSERT INTO clients (id, secret, name, type, redirect_uris, grant_types, created_at, updated_at)
VALUES (
    'web-app-client',
    'web-app-secret-123',
    'Web Application',
    'confidential',
    ARRAY['http://localhost:3000/callback', 'https://app.example.com/callback'],
    ARRAY['authorization_code', 'refresh_token'],
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Insert a public client for SPAs
INSERT INTO clients (id, secret, name, type, redirect_uris, grant_types, created_at, updated_at)
VALUES (
    'spa-client',
    NULL,
    'Single Page Application',
    'public',
    ARRAY['http://localhost:3000/callback', 'https://spa.example.com/callback'],
    ARRAY['authorization_code', 'refresh_token'],
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Insert a machine-to-machine client
INSERT INTO clients (id, secret, name, type, redirect_uris, grant_types, created_at, updated_at)
VALUES (
    'm2m-client',
    'm2m-secret-456',
    'Machine to Machine',
    'confidential',
    ARRAY[],
    ARRAY['client_credentials'],
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Insert a mobile app client
INSERT INTO clients (id, secret, name, type, redirect_uris, grant_types, created_at, updated_at)
VALUES (
    'mobile-app-client',
    'mobile-secret-789',
    'Mobile Application',
    'confidential',
    ARRAY['com.example.app://callback'],
    ARRAY['authorization_code', 'refresh_token', 'password'],
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;
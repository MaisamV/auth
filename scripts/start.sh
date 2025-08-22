#!/bin/sh

# Check if Ed25519 private key exists
if [ ! -f "keys/jwt-ed25519-private.pem" ]; then
    echo "🔑 Ed25519 JWT keys not found, generating new keys..."
    ./keygen-ed25519
else
    echo "🔑 Ed25519 JWT keys found, using existing keys"
fi

# Start the main application
echo "🚀 Starting auth service..."
exec ./main
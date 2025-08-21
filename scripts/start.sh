#!/bin/sh

# Check if Ed25519 private key exists, if not generate keys
if [ ! -f "keys/jwt-ed25519-private.pem" ]; then
    echo "🔑 Ed25519 JWT keys not found, generating new key pair..."
    ./keygen-ed25519
    echo "✅ Ed25519 JWT keys generated successfully!"
else
    echo "🔑 Ed25519 JWT keys found, using existing keys"
fi

# Start the main application
echo "🚀 Starting auth service..."
exec ./main
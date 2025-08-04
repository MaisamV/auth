#!/bin/sh

# Check if private key exists, if not generate keys
if [ ! -f "keys/jwt-private.pem" ]; then
    echo "🔑 JWT keys not found, generating new key pair..."
    ./keygen
    echo "✅ JWT keys generated successfully!"
else
    echo "🔑 JWT keys found, using existing keys"
fi

# Start the main application
echo "🚀 Starting auth service..."
exec ./main
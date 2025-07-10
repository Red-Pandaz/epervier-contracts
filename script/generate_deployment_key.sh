#!/bin/bash

# Generate deployment private key
# This script generates a secure ECDSA private key for contract deployment

echo "🔑 Generating deployment private key..."

# Generate a random private key using openssl
PRIVATE_KEY=$(openssl rand -hex 32)

echo "✅ Private key generated!"
echo ""
echo "🔐 Your private key (keep this secret!):"
echo "$PRIVATE_KEY"
echo ""
echo "📋 Set this as your environment variable:"
echo "export PRIVATE_KEY=$PRIVATE_KEY"
echo ""
echo "⚠️  IMPORTANT:"
echo "   - Keep this private key secure and secret"
echo "   - Never share it or commit it to version control"
echo "   - Make sure your wallet has enough ETH for deployment"
echo ""
echo "💰 You'll need some ETH on OP Sepolia for deployment gas fees"
echo "   Get testnet ETH from: https://sepoliafaucet.com/" 
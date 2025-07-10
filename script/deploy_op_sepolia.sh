#!/bin/bash

# Deploy to OP Sepolia
# Usage: ./deploy_op_sepolia.sh

set -e

# Load environment variables from .env file
if [ -f .env ]; then
    echo "📄 Loading environment variables from .env file..."
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "❌ Error: .env file not found"
    echo "Please create a .env file with the following variables:"
    echo "PRIVATE_KEY=your_private_key_here"
    echo "ETHERSCAN_API_KEY=your_etherscan_api_key_here"
    echo "RPC_URL=https://sepolia.optimism.io (optional)"
    exit 1
fi

echo "🚀 Deploying to OP Sepolia..."

# Check if PRIVATE_KEY is set
if [ -z "$PRIVATE_KEY" ]; then
    echo "❌ Error: PRIVATE_KEY environment variable is not set in .env file"
    echo "Please add PRIVATE_KEY=your_private_key_here to your .env file"
    exit 1
fi

# Check if RPC_URL is set (optional, will use default if not set)
if [ -z "$RPC_URL" ]; then
    echo "⚠️  Warning: RPC_URL not set, using default OP Sepolia RPC"
    export RPC_URL="https://sepolia.optimism.io"
fi

echo "📡 Using RPC URL: $RPC_URL"
echo "🔑 Using private key: ${PRIVATE_KEY:0:10}..."

# Deploy contracts
echo "📦 Deploying contracts..."
forge script script/DeployOPSepolia.s.sol:DeployOPSepolia \
    --rpc-url $RPC_URL \
    --broadcast \
    --verify \
    --etherscan-api-key $ETHERSCAN_API_KEY \
    --verifier-url https://api-sepolia-optimistic.etherscan.io/api

echo "✅ Deployment complete!"
echo ""
echo "📋 Contract addresses will be displayed above."
echo "🔍 You can verify the contracts on Optimistic Etherscan:"
echo "   https://sepolia-optimistic.etherscan.io/" 
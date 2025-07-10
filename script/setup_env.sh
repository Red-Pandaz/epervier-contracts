#!/bin/bash

# Setup environment variables for OP Sepolia deployment
# Usage: source ./script/setup_env.sh

echo "🔧 Setting up environment variables for OP Sepolia deployment..."

# Check if .env file exists, if not create it
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    touch .env
fi

# Function to add or update environment variable
add_env_var() {
    local key=$1
    local value=$2
    local file=".env"
    
    # Remove existing line if it exists
    sed -i.bak "/^${key}=/d" $file
    # Add new line
    echo "${key}=${value}" >> $file
    echo "✅ Set $key"
}

# Set default values
add_env_var "PRIVATE_KEY" "b49660ef7fa1301a20a20d2c5ab59e43c4d1699dce2dd89fa646db6eb3b7f7b3"
add_env_var "RPC_URL" "https://sepolia.optimism.io"
add_env_var "ETHERSCAN_API_KEY" "YOUR_ETHERSCAN_API_KEY_HERE"

echo ""
echo "📋 Environment variables set in .env file:"
echo "   PRIVATE_KEY=b49660ef7fa1301a20a20d2c5ab59e43c4d1699dce2dd89fa646db6eb3b7f7b3"
echo "   RPC_URL=https://sepolia.optimism.io"
echo "   ETHERSCAN_API_KEY=YOUR_ETHERSCAN_API_KEY_HERE"
echo ""
echo "⚠️  IMPORTANT:"
echo "   1. Replace YOUR_ETHERSCAN_API_KEY_HERE with your actual API key"
echo "   2. Get your API key from: https://etherscan.io/apis"
echo "   3. Make sure your wallet has enough ETH for deployment"
echo ""
echo "🔍 To load these variables in your current shell:"
echo "   source .env"
echo ""
echo "🚀 To deploy after setup:"
echo "   ./script/deploy_op_sepolia.sh" 
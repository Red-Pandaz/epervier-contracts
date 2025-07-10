#!/bin/bash

# Load environment variables
source .env

# Check if required environment variables are set
if [ -z "$PRIVATE_KEY" ]; then
    echo "Error: PRIVATE_KEY environment variable is not set"
    exit 1
fi

if [ -z "$RPC_URL" ]; then
    echo "Error: RPC_URL environment variable is not set"
    exit 1
fi

if [ -z "$EPERVIER_VERIFIER_ADDRESS" ]; then
    echo "Error: EPERVIER_VERIFIER_ADDRESS environment variable is not set"
    exit 1
fi

if [ -z "$ETHERSCAN_API_KEY" ]; then
    echo "Error: ETHERSCAN_API_KEY environment variable is not set"
    exit 1
fi

echo "Deploying optimized contracts to OP Sepolia..."
echo "Using RPC URL: $RPC_URL"
echo "Using Epervier Verifier: $EPERVIER_VERIFIER_ADDRESS"

# Run the deployment with optimization enabled
forge script script/DeployOptimized.s.sol:DeployOptimizedScript \
    --rpc-url $RPC_URL \
    --broadcast \
    --verify \
    --etherscan-api-key $ETHERSCAN_API_KEY \
    --optimize \
    --optimizer-runs 200 \
    -vvvv

echo "Deployment completed!" 
#!/bin/bash

# Deploy production contracts to local devnet and extract domain separator

set -e

echo "🚀 Deploying production contracts to local devnet..."

# Start local devnet if not already running
if ! pgrep -f "anvil" > /dev/null; then
    echo "Starting local devnet..."
    anvil &
    ANVIL_PID=$!
    sleep 2
    echo "Local devnet started with PID: $ANVIL_PID"
else
    echo "Local devnet already running"
fi

# Set environment variables
export PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
export RPC_URL="http://localhost:8545"

# Deploy contracts
echo "Deploying contracts..."
forge script script/deploy_production_contracts.sol:DeployProductionContracts \
    --rpc-url $RPC_URL \
    --private-key $PRIVATE_KEY \
    --broadcast \
    --verify

# Extract contract addresses from deployment
echo "Extracting contract addresses..."

# Get the deployed addresses (you'll need to parse the forge output)
echo "Please check the deployment output above for contract addresses"
echo "Then update the production_eip712_config.py with the correct domain separator"

echo "✅ Deployment complete!"
echo ""
echo "Next steps:"
echo "1. Extract the PQRegistry contract address from the deployment output"
echo "2. Update test/python/vector_generators/production/production_eip712_config.py"
echo "3. Compute the correct domain separator using the contract address"
echo "4. Test the production vector generators" 
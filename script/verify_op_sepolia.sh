#!/bin/bash

# Verify contracts on OP Sepolia
# Usage: ./verify_op_sepolia.sh <registry_address> <nft_address>

set -e

if [ $# -ne 2 ]; then
    echo "❌ Error: Please provide both contract addresses"
    echo "Usage: ./verify_op_sepolia.sh <registry_address> <nft_address>"
    echo "Example: ./verify_op_sepolia.sh 0x1234... 0x5678..."
    exit 1
fi

REGISTRY_ADDRESS=$1
NFT_ADDRESS=$2
EPERVIER_VERIFIER="0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"

# Check if ETHERSCAN_API_KEY is set
if [ -z "$ETHERSCAN_API_KEY" ]; then
    echo "❌ Error: ETHERSCAN_API_KEY environment variable is not set"
    echo "Please set your Etherscan API key:"
    echo "export ETHERSCAN_API_KEY=your_api_key_here"
    exit 1
fi

echo "🔍 Verifying contracts on OP Sepolia..."

echo "📋 Registry Address: $REGISTRY_ADDRESS"
echo "📋 NFT Address: $NFT_ADDRESS"
echo "📋 Epervier Verifier: $EPERVIER_VERIFIER"

# Verify PQRegistry
echo "🔍 Verifying PQRegistry..."
forge verify-contract \
    --chain-id 11155420 \
    --etherscan-api-key $ETHERSCAN_API_KEY \
    --verifier-url https://api-sepolia-optimistic.etherscan.io/api \
    $REGISTRY_ADDRESS \
    src/PQRegistry.sol:PQRegistry \
    --constructor-args $(cast abi-encode "constructor(address)" $EPERVIER_VERIFIER)

echo "✅ PQRegistry verification submitted!"

# Verify PQERC721
echo "🔍 Verifying PQERC721..."
forge verify-contract \
    --chain-id 11155420 \
    --etherscan-api-key $ETHERSCAN_API_KEY \
    --verifier-url https://api-sepolia-optimistic.etherscan.io/api \
    $NFT_ADDRESS \
    src/PQERC721.sol:PQERC721 \
    --constructor-args $(cast abi-encode "constructor(string,string)" "PQ NFT" "PQNFT")

echo "✅ PQERC721 verification submitted!"

echo ""
echo "🎉 Verification complete!"
echo "🔍 Check verification status on:"
echo "   https://sepolia-optimistic.etherscan.io/address/$REGISTRY_ADDRESS"
echo "   https://sepolia-optimistic.etherscan.io/address/$NFT_ADDRESS" 
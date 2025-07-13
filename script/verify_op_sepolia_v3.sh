#!/bin/bash

# Verify contracts on OP Sepolia using Etherscan V2 API with Standard JSON
# Usage: ./verify_op_sepolia_v3.sh <registry_address> <nft_address>

set -e

if [ $# -ne 2 ]; then
    echo "❌ Error: Please provide both contract addresses"
    echo "Usage: ./verify_op_sepolia_v3.sh <registry_address> <nft_address>"
    echo "Example: ./verify_op_sepolia_v3.sh 0x1234... 0x5678..."
    exit 1
fi

REGISTRY_ADDRESS=$1
NFT_ADDRESS=$2
EPERVIER_VERIFIER="0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"
CHAIN_ID="11155420"  # OP Sepolia
API_URL="https://api.etherscan.io/api"

# Check if ETHERSCAN_API_KEY is set
if [ -z "$ETHERSCAN_API_KEY" ]; then
    echo "❌ Error: ETHERSCAN_API_KEY environment variable is not set"
    echo "Please set your Etherscan API key:"
    echo "export ETHERSCAN_API_KEY=your_api_key_here"
    exit 1
fi

echo "🔍 Verifying contracts on OP Sepolia using V2 API with Standard JSON..."
echo "📋 Registry Address: $REGISTRY_ADDRESS"
echo "📋 NFT Address: $NFT_ADDRESS"
echo "📋 Epervier Verifier: $EPERVIER_VERIFIER"
echo "📋 Chain ID: $CHAIN_ID"

# Function to generate Standard JSON
generate_standard_json() {
    local target_contract=$1
    
    # Build the contract using forge to get the full compilation artifact
    forge build --force
    
    # Generate standard JSON input
    forge standard-json --contract "$target_contract"
}

# Function to verify contract via V2 API using Standard JSON
verify_contract_v2_json() {
    local contract_address=$1
    local contract_name=$2
    local target_contract=$3
    local constructor_args=$4
    
    echo "🔍 Verifying $contract_name..."
    
    # Generate standard JSON
    local standard_json=$(generate_standard_json "$target_contract")
    
    # Get compiler version
    local solc_version=$(solc --version | grep -o "0\.[0-9]\+\.[0-9]\+" | head -1)
    local commit_hash=$(solc --version | grep -o "+commit\.[a-f0-9]\{8\}" | head -1 | cut -d'.' -f2)
    local full_compiler_version="v${solc_version}+commit.${commit_hash}"
    
    # Make verification request using standard JSON
    local response=$(curl -s -X POST "$API_URL" \
        -F "chainId=$CHAIN_ID" \
        -F "module=contract" \
        -F "action=verifysourcecode" \
        -F "apikey=$ETHERSCAN_API_KEY" \
        -F "contractaddress=$contract_address" \
        -F "sourceCode=$standard_json" \
        -F "codeformat=solidity-standard-json-input" \
        -F "contractname=$contract_name" \
        -F "compilerversion=$full_compiler_version" \
        -F "constructorArguements=$constructor_args")
    
    echo "Response: $response"
    
    # Extract GUID from response
    local guid=$(echo $response | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
    
    if [ -n "$guid" ] && [ "$guid" != "Max rate limit reached" ]; then
        echo "✅ Verification submitted for $contract_name"
        echo "📋 GUID: $guid"
        
        # Wait and check status
        echo "⏳ Waiting for verification to complete..."
        sleep 15
        
        local status_response=$(curl -s "$API_URL?chainId=$CHAIN_ID&module=contract&action=checkverifystatus&guid=$guid&apikey=$ETHERSCAN_API_KEY")
        echo "Status: $status_response"
        
        echo "🔍 Check verification status on:"
        echo "   https://sepolia-optimistic.etherscan.io/address/$contract_address"
    else
        echo "❌ Verification failed for $contract_name"
        echo "Response: $response"
    fi
    
    echo ""
}

# Calculate constructor arguments
echo "🔧 Calculating constructor arguments..."

# PQRegistry constructor args (address)
REGISTRY_CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address)" $EPERVIER_VERIFIER)
echo "📋 Registry constructor args: $REGISTRY_CONSTRUCTOR_ARGS"

# PQERC721 constructor args (string, string)
NFT_CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(string,string)" "PQ NFT" "PQNFT")
echo "📋 NFT constructor args: $NFT_CONSTRUCTOR_ARGS"

# Verify PQRegistry
verify_contract_v2_json "$REGISTRY_ADDRESS" "src/PQRegistry.sol:PQRegistry" "src/PQRegistry.sol:PQRegistry" "${REGISTRY_CONSTRUCTOR_ARGS:2}"

# Verify PQERC721
verify_contract_v2_json "$NFT_ADDRESS" "src/PQERC721.sol:PQERC721" "src/PQERC721.sol:PQERC721" "${NFT_CONSTRUCTOR_ARGS:2}"

echo "🎉 Verification process complete!"
echo ""
echo "🔍 Check all contract verification status on:"
echo "   https://sepolia-optimistic.etherscan.io/address/$REGISTRY_ADDRESS"
echo "   https://sepolia-optimistic.etherscan.io/address/$NFT_ADDRESS" 
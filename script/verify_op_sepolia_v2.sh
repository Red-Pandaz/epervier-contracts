#!/bin/bash

# Verify contracts on OP Sepolia using Etherscan V2 API
# Usage: ./verify_op_sepolia_v2.sh <registry_address> <nft_address>

set -e

if [ $# -ne 2 ]; then
    echo "❌ Error: Please provide both contract addresses"
    echo "Usage: ./verify_op_sepolia_v2.sh <registry_address> <nft_address>"
    echo "Example: ./verify_op_sepolia_v2.sh 0x1234... 0x5678..."
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

echo "🔍 Verifying contracts on OP Sepolia using V2 API..."
echo "📋 Registry Address: $REGISTRY_ADDRESS"
echo "📋 NFT Address: $NFT_ADDRESS"
echo "📋 Epervier Verifier: $EPERVIER_VERIFIER"
echo "📋 Chain ID: $CHAIN_ID"

# Function to get flattened source code
get_flattened_source() {
    local contract_path=$1
    forge flatten $contract_path
}

# Function to verify contract via V2 API
verify_contract_v2() {
    local contract_address=$1
    local contract_name=$2
    local source_file=$3
    local constructor_args=$4
    
    echo "🔍 Verifying $contract_name..."
    
    # Get flattened source code
    local source_code=$(get_flattened_source $source_file)
    
    # Get compiler version in Etherscan format
    local solc_version=$(solc --version | grep -o "0\.[0-9]\+\.[0-9]\+" | head -1)
    local commit_hash=$(solc --version | grep -o "+commit\.[a-f0-9]\{8\}" | head -1 | cut -d'.' -f2)
    local full_compiler_version="v${solc_version}+commit.${commit_hash}"
    
    # Make verification request
    local response=$(curl -s -X POST "$API_URL" \
        -F "chainId=$CHAIN_ID" \
        -F "module=contract" \
        -F "action=verifysourcecode" \
        -F "apikey=$ETHERSCAN_API_KEY" \
        -F "contractaddress=$contract_address" \
        -F "sourceCode=$source_code" \
        -F "codeformat=solidity-single-file" \
        -F "contractname=$contract_name" \
        -F "compilerversion=$full_compiler_version" \
        -F "optimizationUsed=1" \
        -F "runs=50000" \
        -F "constructorArguements=$constructor_args" \
        -F "evmversion=cancun")
    
    echo "Response: $response"
    
    # Extract GUID from response
    local guid=$(echo $response | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
    
    if [ -n "$guid" ] && [ "$guid" != "Max rate limit reached" ]; then
        echo "✅ Verification submitted for $contract_name"
        echo "📋 GUID: $guid"
        
        # Wait and check status
        echo "⏳ Waiting for verification to complete..."
        sleep 10
        
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
verify_contract_v2 "$REGISTRY_ADDRESS" "src/PQRegistry.sol:PQRegistry" "src/PQRegistry.sol" "${REGISTRY_CONSTRUCTOR_ARGS:2}"

# Verify PQERC721
verify_contract_v2 "$NFT_ADDRESS" "src/PQERC721.sol:PQERC721" "src/PQERC721.sol" "${NFT_CONSTRUCTOR_ARGS:2}"

echo "🎉 Verification process complete!"
echo ""
echo "🔍 Check all contract verification status on:"
echo "   https://sepolia-optimistic.etherscan.io/address/$REGISTRY_ADDRESS"
echo "   https://sepolia-optimistic.etherscan.io/address/$NFT_ADDRESS" 
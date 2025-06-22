#!/bin/bash

# Usage: ./verify_epervier_onchain.sh <key_number> <message>
# Example: ./verify_epervier_onchain.sh 1 "This is a transaction"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <key_number> <message>"
    echo "Example: $0 1 'This is a transaction'"
    exit 1
fi

KEY_NUMBER=$1
MESSAGE=$2

# Convert message to hex
MESSAGE_HEX=$(echo -n "$MESSAGE" | xxd -p)

echo "Verifying on-chain message: '$MESSAGE'"
echo "Using keypair #$KEY_NUMBER"
echo "Message hex: $MESSAGE_HEX"

# Check if the keypair and signature exist
if [ ! -f "test_keys/public_key_${KEY_NUMBER}.pem" ]; then
    echo "Error: public_key_${KEY_NUMBER}.pem not found in test_keys/"
    exit 1
fi

if [ ! -f "test_keys/sig_${KEY_NUMBER}" ]; then
    echo "Error: sig_${KEY_NUMBER} not found in test_keys/"
    echo "Please sign the message first using: ./sign_epervier_message.sh $KEY_NUMBER '$MESSAGE'"
    exit 1
fi

# Contract address and RPC
CONTRACT_ADDRESS="0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"
RPC_URL="https://sepolia.optimism.io"

# Get the absolute path to the virtual environment
VENV_PATH="$(pwd)/../../ETHFALCON/python-ref/myenv/bin/python"

# Verify on-chain
$VENV_PATH $(pwd)/../../ETHFALCON/python-ref/sign_cli.py verifyonchain \
    --pubkey=test_keys/public_key_${KEY_NUMBER}.pem \
    --data=$MESSAGE_HEX \
    --signature=test_keys/sig_${KEY_NUMBER} \
    --contractaddress=$CONTRACT_ADDRESS \
    --rpc=$RPC_URL \
    --version='epervier' 
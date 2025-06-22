#!/bin/bash

# Usage: ./sign_epervier_message.sh <key_number> <message>
# Example: ./sign_epervier_message.sh 1 "Register Epervier Key"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <key_number> <message>"
    echo "Example: $0 1 'Register Epervier Key'"
    exit 1
fi

KEY_NUMBER=$1
MESSAGE=$2

# Convert message to hex
MESSAGE_HEX=$(echo -n "$MESSAGE" | xxd -p)

echo "Signing message: '$MESSAGE'"
echo "Using keypair #$KEY_NUMBER"
echo "Message hex: $MESSAGE_HEX"

# Check if the keypair exists
if [ ! -f "test_keys/private_key_${KEY_NUMBER}.pem" ]; then
    echo "Error: private_key_${KEY_NUMBER}.pem not found in test_keys/"
    exit 1
fi

# Get the absolute path to the virtual environment
VENV_PATH="$(pwd)/../../ETHFALCON/python-ref/myenv/bin/python"

# Sign the message
$VENV_PATH $(pwd)/../../ETHFALCON/python-ref/sign_cli.py sign --privkey=test_keys/private_key_${KEY_NUMBER}.pem --data=$MESSAGE_HEX --version='epervier'

# Move the signature to test_keys directory
if [ -f "sig" ]; then
    mv sig test_keys/sig_${KEY_NUMBER}
    echo "Signature saved to test_keys/sig_${KEY_NUMBER}"
else
    echo "Error: Failed to generate signature"
    exit 1
fi
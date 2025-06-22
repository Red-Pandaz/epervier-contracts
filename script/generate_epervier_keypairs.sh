#!/bin/bash

COUNT=${1:-10}  # Default to 10 keypairs if not specified

# Create the test_keys directory if it doesn't exist
mkdir -p test_keys

# Get the absolute path to the virtual environment
VENV_PATH="$(pwd)/../../ETHFALCON/python-ref/myenv/bin/python"

for i in $(seq 1 $COUNT); do
    echo "Generating Epervier keypair #$i..."
    
    # Remove any existing files for this index
    rm -f test_keys/private_key_${i}.pem test_keys/public_key_${i}.pem
    
    # Generate keys using the virtual environment
    $VENV_PATH $(pwd)/../../ETHFALCON/python-ref/sign_cli.py genkeys --version='epervier'
    
    # Move the generated files to the test_keys directory
    if [ -f "private_key.pem" ] && [ -f "public_key.pem" ]; then
        mv -f private_key.pem test_keys/private_key_${i}.pem
        mv -f public_key.pem test_keys/public_key_${i}.pem
        echo "Saved keypair #$i to test_keys/"
    else
        echo "Failed to generate keypair #$i"
        break
    fi
done

echo "Generated $COUNT Epervier keypairs in test_keys/ directory."
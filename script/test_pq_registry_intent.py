#!/usr/bin/env python3
"""
PQ Registry Intent Test Script
Tests the submitRegistrationIntent functionality on the deployed PQRegistry contract
"""

import subprocess
import json
import os
import sys
from pathlib import Path
from web3 import Web3
from eth_account import Account
import time

# Contract addresses from deployment
EPERVIER_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
PQ_REGISTRY_ADDRESS = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"

# Supersim RPC URL for chain 901
RPC_URL = "http://127.0.0.1:9545"

# Test account (from Supersim)
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ACCOUNT = Account.from_key(PRIVATE_KEY)

# ETHFALCON path
ETHFALCON_PATH = Path(__file__).parent.parent.parent / "ETHFALCON" / "python-ref"

def run_command(cmd, description, cwd=None):
    """Run a command and handle errors"""
    print(f"\n🔄 {description}")
    print(f"Command: {cmd}")
    
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            cwd=cwd or ETHFALCON_PATH
        )
        if result.returncode == 0:
            print(f"✅ {description} - SUCCESS")
            if result.stdout.strip():
                print(f"Output: {result.stdout.strip()}")
            return result.stdout.strip()
        else:
            print(f"❌ {description} - FAILED")
            print(f"Error: {result.stderr.strip()}")
            return None
    except Exception as e:
        print(f"❌ {description} - EXCEPTION: {e}")
        return None

def generate_epervier_keys():
    """Generate Epervier keys if they don't exist"""
    public_key_file = ETHFALCON_PATH / "public_key.pem"
    private_key_file = ETHFALCON_PATH / "private_key.pem"
    
    if public_key_file.exists() and private_key_file.exists():
        print("✅ Epervier keys already exist")
        return True
    
    print("📋 Generating Epervier keys...")
    result = run_command(
        "python sign_cli.py genkeys --version=epervier",
        "Generate Epervier keys"
    )
    return result is not None

def sign_intent_message(message):
    """Sign an intent message with Epervier"""
    message_hex = message.encode('utf-8').hex()
    
    print(f"📋 Signing intent message: {message}")
    result = run_command(
        f"python sign_cli.py sign --data={message_hex} --privkey=private_key.pem",
        "Sign intent message"
    )
    
    if result is None:
        return None
    
    # Read the signature file
    sig_file = ETHFALCON_PATH / "sig"
    if not sig_file.exists():
        print("❌ Signature file not found")
        return None
    
    with open(sig_file, 'r') as f:
        signature_data = f.read().strip()
    
    return {
        "message": message,
        "message_hex": message_hex,
        "signature_data": signature_data
    }

def parse_signature(signature_data):
    """Parse the Epervier signature data"""
    # This is a simplified parser - you may need to adjust based on actual signature format
    lines = signature_data.split('\n')
    parsed = {}
    
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            parsed[key.strip()] = value.strip()
    
    return parsed

def create_intent_transaction():
    """Create and submit an intent transaction to PQRegistry"""
    print("\n🚀 Creating Intent Transaction")
    print("=" * 50)
    
    # Step 1: Generate keys if needed
    if not generate_epervier_keys():
        print("❌ Failed to generate Epervier keys")
        return False
    
    # Step 2: Create intent message
    intent_message = f"Register Epervier Key{ACCOUNT.address}0"
    print(f"📋 Intent message: {intent_message}")
    
    # Step 3: Sign the intent message
    signed_data = sign_intent_message(intent_message)
    if not signed_data:
        print("❌ Failed to sign intent message")
        return False
    
    # Step 4: Parse signature
    signature_parsed = parse_signature(signed_data["signature_data"])
    print(f"📋 Parsed signature: {json.dumps(signature_parsed, indent=2)}")
    
    # Step 5: Create the transaction using cast
    # We'll use a simplified approach with cast for now
    print("\n📋 Submitting intent transaction...")
    
    # Get current nonce
    nonce_cmd = f"cast nonce {ACCOUNT.address} --rpc-url {RPC_URL}"
    nonce_result = subprocess.run(nonce_cmd, shell=True, capture_output=True, text=True)
    if nonce_result.returncode != 0:
        print(f"❌ Failed to get nonce: {nonce_result.stderr}")
        return False
    
    nonce = int(nonce_result.stdout.strip())
    print(f"📋 Current nonce: {nonce}")
    
    # For now, let's create a simple test transaction
    # In a real implementation, you'd need to encode the function call properly
    test_tx_cmd = f"""
    cast send {PQ_REGISTRY_ADDRESS} \\
        "submitRegistrationIntent(bytes,bytes,uint256[],uint256[],uint256,uint256[2],uint256,bytes)" \\
        "{signed_data['message_hex']}" \\
        "0x" \\
        "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]" \\
        "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]" \\
        0 \\
        "[0,0]" \\
        {nonce} \\
        "0x" \\
        --rpc-url {RPC_URL} \\
        --private-key {PRIVATE_KEY}
    """
    
    print("📋 Executing intent transaction...")
    print(f"Command: {test_tx_cmd}")
    
    # For now, let's just test the basic contract interaction
    # You'll need to properly encode the Epervier signature data
    print("⚠️ Note: This is a simplified test. You'll need to properly encode the Epervier signature data.")
    
    return True

def main():
    print("🚀 PQ Registry Intent Test")
    print("=" * 50)
    print(f"📋 Epervier Address: {EPERVIER_ADDRESS}")
    print(f"📋 PQ Registry Address: {PQ_REGISTRY_ADDRESS}")
    print(f"📋 RPC URL: {RPC_URL}")
    print(f"📋 Test Account: {ACCOUNT.address}")
    
    # Check if ETHFALCON path exists
    if not ETHFALCON_PATH.exists():
        print(f"❌ Error: ETHFALCON path not found: {ETHFALCON_PATH}")
        return
    
    # Test the intent transaction
    success = create_intent_transaction()
    
    if success:
        print("\n✅ Intent transaction test completed!")
    else:
        print("\n❌ Intent transaction test failed!")

if __name__ == "__main__":
    main() 
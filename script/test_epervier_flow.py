#!/usr/bin/env python3
"""
Epervier Flow Test Script
Generates Epervier keys, signs a message, and tests on-chain recovery
"""

import subprocess
import json
import os
import sys
from pathlib import Path

# Path to ETHFALCON python-ref directory
# From /Users/davidmillstone/Documents/concepts/pq-smart-contracts/script/
# We need to go up to /Users/davidmillstone/Documents/concepts/ then into ETHFALCON/python-ref
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

def main():
    print("🚀 Starting Epervier Flow Test")
    print("=" * 50)
    
    # Check if ETHFALCON path exists
    if not ETHFALCON_PATH.exists():
        print(f"❌ Error: ETHFALCON path not found: {ETHFALCON_PATH}")
        print("Please ensure ETHFALCON is cloned in the parent directory")
        return
    
    print(f"📁 Using ETHFALCON path: {ETHFALCON_PATH}")
    
    # Step 1: Generate Epervier keys
    print("\n📋 Step 1: Generating Epervier keys...")
    result = run_command(
        "python sign_cli.py genkeys --version=epervier",
        "Generate Epervier keys"
    )
    if not result:
        print("❌ Failed to generate keys")
        return
    
    # Step 2: Sign a test message
    print("\n📋 Step 2: Signing test message...")
    test_message = "Hello, ZKNOX Epervier! 🦅"
    message_hex = test_message.encode('utf-8').hex()
    
    result = run_command(
        f"python sign_cli.py sign --data={message_hex} --privkey=private_key.pem",
        "Sign test message"
    )
    
    # Check if signature file was created (sign_cli.py doesn't print output on success)
    sig_file = ETHFALCON_PATH / "sig"
    if sig_file.exists():
        print("✅ Signature file created successfully")
    else:
        print("❌ Failed to sign message - signature file not found")
        return
    
    # Step 3: Test on-chain recovery
    print("\n📋 Step 3: Testing on-chain recovery...")
    contract_address = "0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"
    rpc_url = "https://sepolia.optimism.io"
    
    result = run_command(
        f"python sign_cli.py recoveronchain --data={message_hex} --pubkey=public_key.pem --signature=sig --contractaddress={contract_address} --rpc={rpc_url}",
        "Test on-chain recovery"
    )
    
    if result:
        print("✅ On-chain recovery test completed successfully!")
        # Extract the recovered address from the output
        if "0x" in result:
            recovered_address = result.split("0x")[1][:40]  # Extract 20 bytes (40 hex chars)
            recovered_address = "0x" + recovered_address
            print(f"Recovered address: {recovered_address}")
            
            # Save test data for later use
            test_data = {
                "message": test_message,
                "message_hex": message_hex,
                "recovered_address": recovered_address,
                "contract_address": contract_address,
                "rpc_url": rpc_url,
                "files": {
                    "public_key": "public_key.pem",
                    "private_key": "private_key.pem", 
                    "signature": "sig"
                }
            }
            
            # Save to current directory
            output_file = Path(__file__).parent / "epervier_test_data.json"
            with open(output_file, 'w') as f:
                json.dump(test_data, f, indent=2)
            
            print(f"✅ Test data saved to: {output_file}")
        else:
            print("⚠️ Could not extract recovered address from output")
    else:
        print("❌ On-chain recovery test failed")
    
    print("\n🎉 Epervier flow test completed!")
    print("\nGenerated files:")
    print(f"  - {ETHFALCON_PATH}/public_key.pem (Epervier public key)")
    print(f"  - {ETHFALCON_PATH}/private_key.pem (Epervier private key)")
    print(f"  - {ETHFALCON_PATH}/sig (Epervier signature)")
    print(f"  - {Path(__file__).parent}/epervier_test_data.json (Test data)")

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
Debug script to recover the true fingerprint from a signature using ETHFalcon CLI.
"""

import subprocess
import sys
import os
from pathlib import Path

# Get the script directory for proper path resolution
SCRIPT_DIR = Path(__file__).parent.absolute()

def recover_fingerprint_from_signature(message_hex, salt_hex, cs1, cs2, hint, key_index):
    """Recover fingerprint from signature using ETHFalcon CLI"""
    
    # Path to the ETHFalcon CLI
    SIGN_CLI_PATH = Path(__file__).parent.parent.parent.parent / "ETHFALCON/python-ref/sign_cli.py"
    
    # EPERVIER contract address on Optimism Sepolia
    CONTRACT_ADDRESS = "0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"
    RPC_URL = "https://sepolia.optimism.io"
    
    try:
        print(f"Message (hex): {message_hex}")
        print(f"Salt (hex): {salt_hex}")
        print(f"Hint: {hint}")
        print(f"Key index: {key_index}")
        
        # First, let's create a proper signature file that the CLI can use
        # The CLI expects a specific format, so we need to reconstruct it from our components
        temp_sig_file = SCRIPT_DIR / "temp_sig"
        
        # Convert our signature components back to the CLI format
        # Based on the parse_signature_file function, we need to reconstruct the original format
        HEAD_LEN = 1
        SALT_LEN = 40
        
        # Create the signature bytes in the format expected by the CLI
        # Format: [header][salt][encoded_signature][hint_bytes]
        header = bytes([0x01])  # Assuming header is 0x01
        salt_bytes = bytes.fromhex(salt_hex[2:] if salt_hex.startswith('0x') else salt_hex)
        
        # We need to convert cs1 and cs2 back to the encoded format
        # This is complex, so let's try a different approach
        
        # Let's first test with a known good signature to understand the format
        print("\nTesting with a known good signature first...")
        
        # Generate a test signature with Charlie's key
        test_message = "test_message_for_recovery"
        test_message_hex = test_message.encode().hex()
        
        cmd = [
            "bash", "-c",
            f"cd {SIGN_CLI_PATH.parent} && source myenv/bin/activate && python3 sign_cli.py sign --version epervier --privkey ../../../test/test_keys/private_key_{key_index + 1}.pem --data {test_message_hex}"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(SCRIPT_DIR))
        print(f"Test signing result: {result.returncode}")
        if result.stdout:
            print(f"Test signing stdout: {result.stdout}")
        if result.stderr:
            print(f"Test signing stderr: {result.stderr}")
        
        # Now let's try to verify this test signature on-chain
        if (SIGN_CLI_PATH.parent / "sig").exists():
            test_sig_file = SIGN_CLI_PATH.parent / "sig"
            
            # Get the public key for Charlie
            cmd = [
                "bash", "-c",
                f"cd {SIGN_CLI_PATH.parent} && source myenv/bin/activate && python3 sign_cli.py verifyonchain --pubkey ../../../test/test_keys/public_key_{key_index + 1}.pem --data {test_message_hex} --signature sig --contractaddress {CONTRACT_ADDRESS} --rpc {RPC_URL}"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(SCRIPT_DIR))
            print(f"Test verification result: {result.returncode}")
            if result.stdout:
                print(f"Test verification stdout: {result.stdout}")
            if result.stderr:
                print(f"Test verification stderr: {result.stderr}")
            
            # Clean up test signature
            test_sig_file.unlink()
        
        # Now let's try to create a signature file for our actual signature
        # We need to reconstruct the signature in the format the CLI expects
        print("\nAttempting to reconstruct our signature for on-chain verification...")
        
        # For now, let's try to use the CLI's internal recovery mechanism
        # We'll need to understand how to convert our signature components back
        
        return "Recovery attempt completed - need to implement signature reconstruction"
        
    except Exception as e:
        print(f"Error in recovery: {e}")
        return None

def main():
    """Main function to debug signature recovery"""
    
    # Load the signature data from our generated vector
    print("Loading signature data from generated vector...")
    
    # Read the vector file
    vector_file = SCRIPT_DIR.parent / "test_vectors/revert/confirm_registration_revert_vectors.json"
    
    if not vector_file.exists():
        print(f"Vector file not found: {vector_file}")
        return
    
    import json
    with open(vector_file, 'r') as f:
        vectors = json.load(f)
    
    # Get the pq_fingerprint_mismatch vector (index 7)
    mismatch_vector = None
    for i, vector in enumerate(vectors["confirm_registration_reverts"]):
        if vector["test_name"] == "pq_fingerprint_mismatch":
            mismatch_vector = vector
            print(f"Found pq_fingerprint_mismatch vector at index {i}")
            break
    
    if not mismatch_vector:
        print("pq_fingerprint_mismatch vector not found")
        return
    
    print(f"Vector data:")
    print(f"  eth_address: {mismatch_vector['eth_address']}")
    print(f"  pq_fingerprint: {mismatch_vector['pq_fingerprint']}")
    print(f"  pq_nonce: {mismatch_vector['pq_nonce']}")
    print(f"  pq_message length: {len(bytes.fromhex(mismatch_vector['pq_message']))} bytes")
    print(f"  pq_signature salt: {mismatch_vector['pq_signature']['salt']}")
    print(f"  pq_signature hint: {mismatch_vector['pq_signature']['hint']}")
    
    # Try to recover the fingerprint
    print("\nAttempting to recover fingerprint from signature...")
    recovered = recover_fingerprint_from_signature(
        mismatch_vector['pq_message'],
        mismatch_vector['pq_signature']['salt'],
        mismatch_vector['pq_signature']['cs1'],
        mismatch_vector['pq_signature']['cs2'],
        mismatch_vector['pq_signature']['hint'],
        2  # Charlie's key index
    )
    
    print(f"Recovery result: {recovered}")

if __name__ == "__main__":
    main() 
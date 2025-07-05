#!/usr/bin/env python3
"""
Recover fingerprint from signature using ETHFalcon CLI.
"""

import json
import subprocess
import sys
import os
from pathlib import Path

# Get the script directory for proper path resolution
SCRIPT_DIR = Path(__file__).parent.absolute()

# Constants
CONTRACT_ADDRESS = "0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"
RPC_URL = "https://sepolia.optimism.io"

def create_signature_file_from_vector(salt_hex, cs1, cs2, hint, output_file="temp_sig"):
    """Create a signature file from test vector data"""
    try:
        # Convert salt to bytes
        salt_bytes = bytes.fromhex(salt_hex[2:] if salt_hex.startswith('0x') else salt_hex)
        
        # Create signature file format
        # Based on the signature format used by ETHFalcon
        header = bytes([0x01])  # Version header
        
        # Convert cs1 and cs2 arrays to bytes
        cs1_bytes = b''
        cs2_bytes = b''
        for val in cs1:
            cs1_bytes += val.to_bytes(32, 'big')
        for val in cs2:
            cs2_bytes += val.to_bytes(32, 'big')
        
        # Create the signature file content
        signature_bytes = header + salt_bytes + cs1_bytes + cs2_bytes + hint.to_bytes(32, 'big')
        
        with open(output_file, 'wb') as f:
            f.write(signature_bytes)
        
        print(f"Created signature file from vector data: {output_file}")
        return output_file
        
    except Exception as e:
        print(f"Error creating signature file: {e}")
        return None

def recover_fingerprint_onchain(message_hex, salt_hex, cs1, cs2, hint, key_index):
    """Recover fingerprint using ETHFalcon CLI on-chain verification"""
    
    # Path to the ETHFalcon CLI
    SIGN_CLI_PATH = Path(__file__).parent.parent.parent.parent / "ETHFALCON/python-ref/sign_cli.py"
    
    try:
        print(f"Recovering fingerprint for key index {key_index}...")
        print(f"Message length: {len(message_hex)//2} bytes")
        print(f"Salt: {salt_hex[:20]}...")
        print(f"Hint: {hint}")
        
        # Create signature file from test vector data
        sig_file = str(Path(create_signature_file_from_vector(salt_hex, cs1, cs2, hint)).resolve())
        if not sig_file:
            return None
        
        # Use absolute path for public key
        pubkey_file = (SCRIPT_DIR.parent / "test_keys" / f"public_key_{key_index + 1}.pem").resolve()
        
        # Use ETHFalcon CLI to verify on-chain and recover fingerprint
        cmd = [
            "bash", "-c",
            f"cd {SIGN_CLI_PATH.parent} && source myenv/bin/activate && python3 sign_cli.py verifyonchain --pubkey {pubkey_file} --data {message_hex} --signature {sig_file} --contractaddress {CONTRACT_ADDRESS} --rpc {RPC_URL}"
        ]
        
        print(f"Running command: {' '.join(cmd[2:])}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(SIGN_CLI_PATH.parent))
        
        print(f"Command result: {result.returncode}")
        if result.stdout:
            print(f"STDOUT: {result.stdout}")
        if result.stderr:
            print(f"STDERR: {result.stderr}")
        
        # Clean up temporary signature file
        if os.path.exists(sig_file):
            os.remove(sig_file)
        
        if result.returncode == 0:
            # Parse the output to get the recovered fingerprint
            output_lines = result.stdout.strip().split('\n')
            for line in output_lines:
                if line.startswith('0x') and len(line) == 42:  # Ethereum address format
                    return line
            return "Verification successful but no fingerprint found in output"
        else:
            return f"Verification failed with return code {result.returncode}"
        
    except Exception as e:
        print(f"Error in on-chain recovery: {e}")
        return None

def load_vector_from_file(vector_file, test_name="pq_fingerprint_mismatch"):
    """Load test vector from file"""
    try:
        with open(vector_file, 'r') as f:
            data = json.load(f)
        
        # Find the specific test vector
        for i, vector in enumerate(data.get("confirm_registration_reverts", [])):
            if vector.get("test_name") == test_name:
                print(f"Found {test_name} vector at index {i}")
                return vector
        
        print(f"Test vector '{test_name}' not found")
        return None
        
    except Exception as e:
        print(f"Error loading vector file: {e}")
        return None

def main():
    """Main function to recover fingerprint from signature"""
    
    if len(sys.argv) < 2:
        print("Usage: python3 recover_fingerprint.py <vector_file> [test_name] [key_index]")
        print("Example: python3 recover_fingerprint.py test_vectors/revert/confirm_registration_revert_vectors.json pq_fingerprint_mismatch 2")
        return
    
    vector_file = sys.argv[1]
    test_name = sys.argv[2] if len(sys.argv) > 2 else "pq_fingerprint_mismatch"
    key_index = int(sys.argv[3]) if len(sys.argv) > 3 else 2
    
    print(f"Loading vector from: {vector_file}")
    print(f"Test name: {test_name}")
    print(f"Key index: {key_index}")
    
    # Load the test vector
    vector = load_vector_from_file(vector_file, test_name)
    if not vector:
        return
    
    # Extract signature components
    message_hex = vector["pq_message"]
    salt_hex = vector["pq_signature"]["salt"]
    cs1 = vector["pq_signature"]["cs1"]
    cs2 = vector["pq_signature"]["cs2"]
    hint = vector["pq_signature"]["hint"]
    
    print(f"\nVector data:")
    print(f"  eth_address: {vector['eth_address']}")
    print(f"  pq_fingerprint: {vector['pq_fingerprint']}")
    print(f"  pq_nonce: {vector['pq_nonce']}")
    print(f"  pq_message length: {len(message_hex)//2} bytes")
    print(f"  pq_signature salt: {salt_hex[:20]}...")
    print(f"  pq_signature hint: {hint}")
    
    # Recover fingerprint
    print(f"\nAttempting to recover fingerprint...")
    recovered_fingerprint = recover_fingerprint_onchain(message_hex, salt_hex, cs1, cs2, hint, key_index)
    
    if recovered_fingerprint:
        print(f"\nRecovered fingerprint: {recovered_fingerprint}")
        print(f"Expected fingerprint: {vector['pq_fingerprint']}")
        
        if recovered_fingerprint.lower() == vector['pq_fingerprint'].lower():
            print("✅ Fingerprints match!")
        else:
            print("❌ Fingerprints do not match!")
    else:
        print("Failed to recover fingerprint")

if __name__ == "__main__":
    main() 
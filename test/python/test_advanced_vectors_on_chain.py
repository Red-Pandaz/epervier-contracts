#!/usr/bin/env python3
"""
Test advanced vectors on the actual testnet contract.
Extracts message and signature data from our advanced vectors and tests them
using the ETHFalcon sign_cli.py tool.
"""

import json
import subprocess
import sys
import os
from pathlib import Path

# Contract address for EPERVIER on Optimism Sepolia
CONTRACT_ADDRESS = "0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"
RPC_URL = "https://sepolia.optimism.io"

def load_advanced_vectors(vector_type="registration_intent"):
    """Load the advanced vectors from the generated file."""
    vectors_file = Path(f"../test_vectors/{vector_type}_vectors.json")
    if not vectors_file.exists():
        print(f"Error: Advanced vectors file not found at {vectors_file}")
        return None
    
    with open(vectors_file, 'r') as f:
        return json.load(f)

def extract_pq_signature_data(vector):
    """Extract PQ signature data from a vector."""
    # For registration intents, the PQ signature is nested inside the ETH signature
    # We need to extract the base message that was signed with PQ
    if 'pq_signature' in vector:
        return {
            'message': vector['base_message'],
            'signature': vector['pq_signature'],
            'type': 'pq_only'
        }
    elif 'eth_signature' in vector and 'pq_signature' in vector:
        # For confirmations, we have both ETH and PQ signatures
        return {
            'message': vector['base_message'],
            'signature': vector['pq_signature'],
            'type': 'pq_nested'
        }
    else:
        return None

def test_signature_on_chain(message_hex, signature_file, description):
    """Test a signature on the testnet contract using sign_cli.py."""
    print(f"\n=== Testing {description} ===")
    print(f"Message (hex): {message_hex}")
    print(f"Signature file: {signature_file}")
    
    # Create a temporary signature file
    temp_sig_file = f"temp_sig_{description.lower().replace(' ', '_')}"
    with open(temp_sig_file, 'wb') as f:
        f.write(bytes.fromhex(signature_file))
    
    try:
        # Use the sign_cli.py tool to verify on chain
        cmd = [
            "python3", "ETHFALCON/python-ref/sign_cli.py",
            "verifyonchain",
            "--version=epervier",
            "--data=" + message_hex,
            "--signature=" + temp_sig_file,
            "--contractaddress=" + CONTRACT_ADDRESS,
            "--rpc=" + RPC_URL
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        print(f"Return code: {result.returncode}")
        print(f"Stdout: {result.stdout}")
        print(f"Stderr: {result.stderr}")
        
        if result.returncode == 0:
            print("✅ SUCCESS: Signature verified on chain!")
            return True
        else:
            print("❌ FAILED: Signature verification failed")
            return False
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False
    finally:
        # Clean up temporary file
        if os.path.exists(temp_sig_file):
            os.remove(temp_sig_file)

def main():
    """Main function to test advanced vectors on chain."""
    print("Testing Advanced Vectors on Optimism Sepolia Testnet")
    print(f"Contract Address: {CONTRACT_ADDRESS}")
    print(f"RPC URL: {RPC_URL}")
    
    # Test with registration intent vectors first
    vector_type = "registration_intent"
    print(f"\nTesting {vector_type} vectors...")
    
    # Load advanced vectors
    vectors = load_advanced_vectors(vector_type)
    if not vectors:
        return
    
    print(f"\nLoaded type: {type(vectors)}")
    print(f"Top-level keys: {list(vectors.keys()) if isinstance(vectors, dict) else 'N/A'}")
    
    # Try to get the actual list of vectors
    if isinstance(vectors, dict):
        # Try common keys
        for key in ['vectors', 'data', 'test_vectors', 'items']:
            if key in vectors:
                vectors_list = vectors[key]
                print(f"Found vectors under key '{key}' (length: {len(vectors_list)})")
                break
        else:
            # If no common key found, just take the first list value
            for v in vectors.values():
                if isinstance(v, list):
                    vectors_list = v
                    print(f"Found vectors as first list value (length: {len(vectors_list)})")
                    break
            else:
                print("No list of vectors found in the loaded data.")
                return
    else:
        vectors_list = vectors
        print(f"Vectors is a list (length: {len(vectors_list)})")
    
    # Test each vector (limit to first 3 for testing)
    success_count = 0
    total_count = 0
    
    for i, vector in enumerate(vectors_list[:3]):  # Test first 3 vectors
        print(f"\n--- Vector {i+1}/3 ---")
        
        # Extract PQ signature data
        pq_data = extract_pq_signature_data(vector)
        if not pq_data:
            print("Skipping vector - no PQ signature data found")
            continue
        
        total_count += 1
        
        # Convert message to hex if it's not already
        message = pq_data['message']
        if isinstance(message, str) and not message.startswith('0x'):
            message_hex = message.encode('utf-8').hex()
        else:
            message_hex = message if message.startswith('0x') else '0x' + message
        
        # Remove 0x prefix for the CLI tool
        if message_hex.startswith('0x'):
            message_hex = message_hex[2:]
        
        # Test the signature
        success = test_signature_on_chain(
            message_hex, 
            pq_data['signature'], 
            f"Vector {i+1} - {pq_data['type']}"
        )
        
        if success:
            success_count += 1
    
    print(f"\n=== SUMMARY ===")
    print(f"Total vectors tested: {total_count}")
    print(f"Successful verifications: {success_count}")
    print(f"Failed verifications: {total_count - success_count}")
    print(f"Success rate: {success_count/total_count*100:.1f}%" if total_count > 0 else "No vectors tested")

if __name__ == "__main__":
    main() 
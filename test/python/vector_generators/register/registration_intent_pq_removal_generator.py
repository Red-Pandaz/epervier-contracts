#!/usr/bin/env python3
"""
Generate test vectors for PQ-side registration removal in PQRegistry

This script generates test vectors for:
- PQ-side removal of registration intents (removeIntentByPQ)

The vectors include the necessary message construction and PQ signing using Falcon.
"""

import json
import os
import sys
import subprocess
from pathlib import Path
import binascii
from eth_utils import keccak

# Add the project root to the Python path
project_root = Path(__file__).resolve().parents[3]  # epervier-registry
sys.path.insert(0, str(project_root))

# Add ETHFALCON to the path for imports
sys.path.insert(0, str(project_root / "ETHFALCON" / "python-ref"))

# Load actors configuration
ACTORS_CONFIG_PATH = project_root / "test" / "test_keys" / "actors_config.json"

def get_actor_config():
    """Load the actors config JSON."""
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]

# Domain separator from the contract (as bytes32)
DOMAIN_SEPARATOR = keccak(b"PQRegistry")

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')

def create_remove_registration_message(domain_separator, eth_address, pq_nonce):
    """
    Create PQ message for removing registration intent
    Format: DOMAIN_SEPARATOR + "Remove registration intent from ETH Address " + ethAddress + pqNonce
    This is signed by the PQ key
    """
    pattern = b"Remove registration intent from ETH Address "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(eth_address[2:]) +  # Remove "0x" prefix
        pq_nonce.to_bytes(32, "big")
    )
    return message

def sign_pq_message(message, pq_private_key_file):
    """Sign a message with PQ private key using sign_cli.py"""
    # Create temporary message file
    message_file = f"/tmp/pq_removal_message.hex"
    with open(message_file, 'w') as f:
        f.write(message.hex())
    
    try:
        # Sign with PQ key using sign_cli.py
        sign_cli = str(project_root / "ETHFALCON" / "python-ref" / "sign_cli.py")
        privkey_path = str(project_root / "test" / "test_keys" / pq_private_key_file)
        
        cmd = [
            "python3", sign_cli, "sign",
            f"--privkey={privkey_path}",
            f"--data={message.hex()}",
            "--version=epervier"
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=project_root / "ETHFALCON" / "python-ref")
        
        if result.returncode != 0:
            print(f"Error signing message: {result.stderr}")
            return None
        
        print(f"PQ sign_cli output:")
        print(result.stdout)
        
        # Parse the signature components from stdout
        lines = result.stdout.splitlines()
        signature_data = {}
        for line in lines:
            if line.startswith("salt:"):
                signature_data["salt"] = bytes.fromhex(line.split()[1])
            elif line.startswith("hint:"):
                signature_data["hint"] = int(line.split()[1])
            elif line.startswith("cs1:"):
                signature_data["cs1"] = [int(x, 16) for x in line.split()[1:]]
            elif line.startswith("cs2:"):
                signature_data["cs2"] = [int(x, 16) for x in line.split()[1:]]
        
        if not all(key in signature_data for key in ["salt", "hint", "cs1", "cs2"]):
            print(f"Failed to parse signature components")
            return None
        
        return {
            "salt": signature_data["salt"].hex(),
            "hint": signature_data["hint"],
            "cs1": [hex(x) for x in signature_data["cs1"]],
            "cs2": [hex(x) for x in signature_data["cs2"]]
        }
        
    finally:
        # Clean up temporary files
        if os.path.exists(message_file):
            os.remove(message_file)

def generate_pq_removal_vectors():
    """Generate test vectors for PQ-side registration removal"""
    
    pq_removal_vectors = []
    actors = get_actor_config()
    
    for actor_name, actor_data in actors.items():
        print(f"Generating PQ removal vector for {actor_name}...")
        
        # PQ-side removal vector
        pq_nonce = 1  # Nonce after submitting registration intent
        pq_message = create_remove_registration_message(DOMAIN_SEPARATOR, actor_data["eth_address"], pq_nonce)
        pq_signature = sign_pq_message(pq_message, actor_data["pq_private_key_file"])
        
        if pq_signature is None:
            print(f"Failed to generate PQ signature for {actor_name}")
            continue
        
        pq_vector = {
            "actor": actor_name,
            "eth_address": actor_data["eth_address"],
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "pq_message": "0x" + pq_message.hex(),
            "pq_signature": pq_signature,
            "pq_nonce": pq_nonce
        }
        pq_removal_vectors.append(pq_vector)
    
    return pq_removal_vectors

def main():
    """Main function to generate and save test vectors"""
    print("Generating PQ-side registration removal test vectors...")
    
    try:
        vectors = generate_pq_removal_vectors()
        
        # Save to JSON file
        output_file = project_root / "test" / "test_vectors" / "registration_pq_removal_vectors.json"
        with open(output_file, 'w') as f:
            json.dump({"registration_pq_removal": vectors}, f, indent=2)
        
        print(f"Generated {len(vectors)} PQ removal vectors")
        print(f"Vectors saved to {output_file}")
        
        # Print sample vector for verification
        if vectors:
            print("\nSample PQ removal vector:")
            sample = vectors[0]
            print(f"Actor: {sample['actor']}")
            print(f"ETH Address: {sample['eth_address']}")
            print(f"PQ Fingerprint: {sample['pq_fingerprint']}")
            print(f"Message: {sample['pq_message']}")
            print(f"Nonce: {sample['pq_nonce']}")
        
    except Exception as e:
        print(f"Error generating vectors: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
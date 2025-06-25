#!/usr/bin/env python3
"""
Generate test vectors for ETH-side registration removal in PQRegistry

This script generates test vectors for:
- ETH-side removal of registration intents (removeIntent)

The vectors include the necessary message construction and ETH signing.
"""

import json
import os
import sys
from pathlib import Path
from eth_account import Account
from eth_utils import keccak, to_hex

# Add the project root to the Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Load actors configuration
ACTORS_CONFIG_PATH = project_root / "test" / "test_keys" / "actors_config.json"

def get_actor_config():
    """Load the actors config JSON."""
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]

# Compute the domain separator (keccak256 of "PQRegistry")
DOMAIN_SEPARATOR_BYTES = keccak(b"PQRegistry")

def create_eth_removal_message(actor_data, eth_nonce):
    """
    Create ETH-side removal message for registration intent
    Format: abi.encodePacked(DOMAIN_SEPARATOR, "Remove registration intent from address", pqFingerprint, ethNonce)
    """
    msg = (
        DOMAIN_SEPARATOR_BYTES +
        b"Remove registration intent from address" +
        bytes.fromhex(actor_data["pq_fingerprint"][2:]) +
        eth_nonce.to_bytes(32, "big")
    )
    return msg

def sign_eth_message(message_bytes, private_key):
    """Sign a message with ETH private key (Ethereum Signed Message)"""
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message_bytes)).encode()
    eth_signed_message = prefix + message_bytes
    eth_signed_message_hash = keccak(eth_signed_message)
    account = Account.from_key(private_key)
    sig = Account._sign_hash(eth_signed_message_hash, private_key=account.key)
    return {
        "v": sig.v,
        "r": sig.r,
        "s": sig.s
    }

def generate_eth_removal_vectors():
    """Generate test vectors for ETH-side registration removal"""
    
    eth_removal_vectors = []
    actors = get_actor_config()
    
    for actor_name, actor_data in actors.items():
        print(f"Generating ETH removal vector for {actor_name}...")
        
        # Generate removal message with nonce 1 (after intent submission)
        eth_nonce = 1  # Nonce after submitting registration intent
        eth_message_bytes = create_eth_removal_message(actor_data, eth_nonce)
        eth_signature = sign_eth_message(eth_message_bytes, actor_data["eth_private_key"])
        
        eth_vector = {
            "actor": actor_name,
            "eth_address": actor_data["eth_address"],
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "eth_message": to_hex(eth_message_bytes),
            "eth_signature": eth_signature,
            "eth_nonce": eth_nonce
        }
        eth_removal_vectors.append(eth_vector)
    
    return eth_removal_vectors

def main():
    """Main function to generate and save test vectors"""
    print("Generating ETH-side registration removal test vectors...")
    
    try:
        vectors = generate_eth_removal_vectors()
        
        # Save to JSON file
        output_file = project_root / "test" / "test_vectors" / "registration_eth_removal_vectors.json"
        with open(output_file, 'w') as f:
            json.dump({"registration_eth_removal": vectors}, f, indent=2)
        
        print(f"Generated {len(vectors)} ETH removal vectors")
        print(f"Vectors saved to {output_file}")
        
        # Print sample vector for verification
        print("\nSample ETH removal vector:")
        sample = vectors[0]
        print(f"Actor: {sample['actor']}")
        print(f"ETH Address: {sample['eth_address']}")
        print(f"PQ Fingerprint: {sample['pq_fingerprint']}")
        print(f"Message (hex): {sample['eth_message']}")
        print(f"Nonce: {sample['eth_nonce']}")
        
    except Exception as e:
        print(f"Error generating vectors: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
Generator for cancel registration intent test vectors.
"""

import json
import sys
from pathlib import Path
from eth_account import Account
from eth_hash.auto import keccak

# Add the project root to the path
project_root = Path(__file__).resolve().parents[4]  # epervier-registry
sys.path.append(str(project_root))

# Add the python directory to the path for EIP712 imports
sys.path.append(str(Path(__file__).resolve().parents[2]))
from eip712_helpers import *
from eip712_config import *

def get_actor_config():
    """Load actor configuration from JSON file"""
    config_file = project_root / "test/test_keys/actors_config.json"
    with open(config_file, 'r') as f:
        config = json.load(f)
        return config["actors"]

def create_remove_registration_message(pq_fingerprint, eth_nonce):
    """
    Create ETH message for removing registration intent
    Format: "Remove registration intent from Epervier Fingerprint " + pqFingerprint + ethNonce
    This is signed by the ETH Address (no domain separator in content)
    """
    pattern = b"Remove registration intent from Epervier Fingerprint "
    message = (
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, "big")
    )
    return message

def sign_eth_message(message, eth_private_key, pq_fingerprint, eth_nonce):
    """Sign a message with ETH private key using EIP712"""
    # Use EIP712 structured signing
    domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    struct_hash = get_remove_intent_struct_hash(pq_fingerprint, eth_nonce)
    signature = sign_eip712_message(eth_private_key, domain_separator, struct_hash)
    return signature

def generate_remove_registration_intent_vectors():
    """Generate test vectors for removing registration intents for all 10 actors"""
    remove_vectors = []
    actors = get_actor_config()
    actor_names = list(actors.keys())
    num_actors = len(actor_names)

    for i in range(num_actors):
        current_actor_name = actor_names[i]
        current_actor = actors[current_actor_name]

        print(f"Generating remove registration intent vector for {current_actor_name}...")

        eth_address = current_actor["eth_address"]
        pq_fingerprint = current_actor["pq_fingerprint"]
        eth_private_key = current_actor["eth_private_key"]

        # Nonces for remove operation
        eth_nonce = 1  # ETH nonce for remove operation

        # Create the ETH remove message and sign it with ETH key
        eth_message = create_remove_registration_message(pq_fingerprint, eth_nonce)
        eth_signature = sign_eth_message(eth_message, eth_private_key, pq_fingerprint, eth_nonce)
        
        if eth_signature is None:
            print(f"Failed to generate ETH signature for {current_actor_name}")
            continue

        remove_vector = {
            "current_actor": current_actor_name,
            "eth_address": eth_address,
            "pq_fingerprint": pq_fingerprint,
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "eth_nonce": eth_nonce
        }
        remove_vectors.append(remove_vector)

    return remove_vectors

def main():
    """Main function to generate and save test vectors"""
    print("Generating remove registration intent test vectors...")
    
    try:
        vectors = generate_remove_registration_intent_vectors()
        
        # Save to JSON file
        output_file = project_root / "test/test_vectors/register/registration_eth_removal_vectors.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump({"registration_eth_removal": vectors}, f, indent=2)
        
        print(f"Generated {len(vectors)} remove registration intent vectors")
        print(f"Vectors saved to {output_file}")
        
        # Print sample vector for verification
        if vectors:
            print("\nSample remove registration intent vector:")
            vector = vectors[0]
            print(f"Current Actor: {vector['current_actor']}")
            print(f"ETH Address: {vector['eth_address']}")
            print(f"PQ Fingerprint: {vector['pq_fingerprint']}")
            print(f"ETH Nonce: {vector['eth_nonce']}")
        
    except Exception as e:
        print(f"Error generating vectors: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
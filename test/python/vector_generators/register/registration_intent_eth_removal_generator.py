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

# Domain separator (same as in the contract)
DOMAIN_SEPARATOR = bytes.fromhex("5f5d847b41fe04c02ecf9746150300028bfc195e7981ae8fe39fe8b7a745650f")

def get_actor_config():
    """Load actor configuration from JSON file"""
    config_file = project_root / "test/test_keys/actors_config.json"
    with open(config_file, 'r') as f:
        config = json.load(f)
        return config["actors"]

def create_remove_registration_message(domain_separator, pq_fingerprint, eth_nonce):
    """
    Create ETH message for removing registration intent
    Format: DOMAIN_SEPARATOR + "Remove registration intent from Epervier Fingerprint " + pqFingerprint + ethNonce
    This is signed by the ETH Address
    """
    pattern = b"Remove registration intent from Epervier Fingerprint "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, "big")
    )
    return message

def sign_eth_message(message, eth_private_key):
    """Sign a message with ETH private key"""
    from eth_account import Account
    
    # Use Ethereum's personal_sign format
    eth_message_length = len(message)
    eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + message
    eth_message_hash = keccak(eth_signed_message)
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(eth_message_hash, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}

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
        eth_message = create_remove_registration_message(DOMAIN_SEPARATOR, pq_fingerprint, eth_nonce)
        eth_signature = sign_eth_message(eth_message, eth_private_key)
        
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
        with open(output_file, 'w') as f:
            json.dump({"remove_registration_intent": vectors}, f, indent=2)
        
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
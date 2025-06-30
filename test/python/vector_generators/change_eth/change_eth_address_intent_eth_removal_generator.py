#!/usr/bin/env python3
"""
Generator for ETH cancel change ETH address intent test vectors.
"""

import json
import sys
from pathlib import Path
from eth_account import Account
from eth_hash.auto import keccak

# Add the project root to the path
project_root = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(project_root / "ETHFALCON" / "python-ref"))

# Domain separator (same as in the contract)
DOMAIN_SEPARATOR = bytes.fromhex("5f5d847b41fe04c02ecf9746150300028bfc195e7981ae8fe39fe8b7a745650f")

def get_actor_config():
    """Load actor configuration from JSON file"""
    config_file = project_root / "test" / "test_keys" / "actors_config.json"
    with open(config_file, 'r') as f:
        config = json.load(f)
        return config["actors"]

def create_eth_cancel_change_eth_address_message(domain_separator, pq_fingerprint, eth_nonce):
    """
    Create ETH message for canceling change ETH address intent
    Format: DOMAIN_SEPARATOR + "Remove change intent from Epervier Fingerprint " + pqFingerprint + ethNonce
    This is signed by the ETH key
    """
    pattern = b"Remove change intent from Epervier Fingerprint "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, "big")
    )
    return message

def sign_eth_message(message_bytes, private_key):
    """Sign a message with ETH private key (Ethereum Signed Message)"""
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message_bytes)).encode()
    eth_signed_message = prefix + message_bytes
    eth_signed_message_hash = keccak(eth_signed_message)
    account = Account.from_key(private_key)
    sig = Account._sign_hash(eth_signed_message_hash, private_key=account.key)
    return {
        "v": sig.v,
        "r": hex(sig.r),
        "s": hex(sig.s)
    }

def generate_eth_cancel_change_eth_address_intent_vectors():
    """Generate test vectors for ETH canceling change ETH address intents for all 10 actors"""
    cancel_vectors = []
    actors = get_actor_config()
    actor_names = list(actors.keys())
    num_actors = len(actor_names)

    for i in range(num_actors):
        current_actor_name = actor_names[i]
        next_actor_name = actor_names[(i + 1) % num_actors]  # Get the next actor (Bob)
        current_actor = actors[current_actor_name]
        next_actor = actors[next_actor_name]  # Bob, who is the new ETH address

        print(f"Generating ETH cancel change ETH address intent vector for {current_actor_name} -> {next_actor_name}...")

        current_eth_address = current_actor["eth_address"]  # Alice's address
        next_eth_address = next_actor["eth_address"]  # Bob's address
        pq_fingerprint = current_actor["pq_fingerprint"]  # Alice's PQ fingerprint
        eth_private_key = next_actor["eth_private_key"]  # Bob's ETH private key (the new address)

        # Nonces for cancel operation
        pq_nonce = 3  # PQ nonce for cancel operation
        eth_nonce = 1  # ETH nonce for cancel operation (Bob's nonce)

        # Create the ETH cancel message and sign it with ETH key
        eth_message = create_eth_cancel_change_eth_address_message(DOMAIN_SEPARATOR, pq_fingerprint, eth_nonce)
        eth_signature = sign_eth_message(eth_message, eth_private_key)
        
        if eth_signature is None:
            print(f"Failed to generate ETH signature for {current_actor_name} -> {next_actor_name}")
            continue

        cancel_vector = {
            "current_actor": current_actor_name,
            "current_eth_address": current_eth_address,
            "next_eth_address": next_eth_address,
            "pq_fingerprint": pq_fingerprint,
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "pq_nonce": pq_nonce,
            "eth_nonce": eth_nonce
        }
        cancel_vectors.append(cancel_vector)

    return cancel_vectors

def main():
    """Main function to generate and save test vectors"""
    print("Generating ETH cancel change ETH address intent test vectors...")
    
    try:
        vectors = generate_eth_cancel_change_eth_address_intent_vectors()
        
        # Save to JSON file
        output_file = project_root / "test/test_vectors/change_eth/change_eth_address_cancel_eth_vectors.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump({"change_eth_address_cancel_eth": vectors}, f, indent=2)
        
        print(f"Generated {len(vectors)} ETH cancel change ETH address intent vectors")
        print(f"Vectors saved to {output_file}")
        
        # Print sample vector for verification
        if vectors:
            print("\nSample ETH cancel change ETH address intent vector:")
            vector = vectors[0]
            print(f"Current Actor: {vector['current_actor']}")
            print(f"Current ETH Address: {vector['current_eth_address']}")
            print(f"Next ETH Address: {vector['next_eth_address']}")
            print(f"PQ Fingerprint: {vector['pq_fingerprint']}")
            print(f"PQ Nonce: {vector['pq_nonce']}")
            print(f"ETH Nonce: {vector['eth_nonce']}")
        
    except Exception as e:
        print(f"Error generating vectors: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
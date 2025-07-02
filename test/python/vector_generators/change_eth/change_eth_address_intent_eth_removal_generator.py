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
sys.path.insert(0, str(project_root / "test" / "python"))

from eip712_helpers import get_remove_change_intent_struct_hash, get_domain_separator, sign_eip712_message
from eip712_config import DOMAIN_SEPARATOR

def get_actor_config():
    """Load actor configuration from JSON file"""
    config_file = project_root / "test" / "test_keys" / "actors_config.json"
    with open(config_file, 'r') as f:
        config = json.load(f)
        return config["actors"]

def create_eth_cancel_change_eth_address_message(pq_fingerprint, eth_nonce):
    """
    Create ETH message for canceling change ETH address intent
    Format: "Remove change intent from Epervier Fingerprint " + pqFingerprint + ethNonce
    This is just for parsing, not for signing
    """
    pattern = b"Remove change intent from Epervier Fingerprint "
    
    # DEBUG: Check pq_fingerprint length
    pq_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove "0x" prefix
    print(f"DEBUG: pq_fingerprint: {pq_fingerprint}")
    print(f"DEBUG: pq_fingerprint length: {len(pq_bytes)} bytes")
    print(f"DEBUG: pq_fingerprint hex: {pq_bytes.hex()}")
    
    message = (
        pattern +
        pq_bytes +
        eth_nonce.to_bytes(32, "big")
    )
    return message

def sign_eth_message_eip712(pq_fingerprint, eth_nonce, private_key):
    """Sign a message with ETH private key using EIP-712 standards"""
    # Get the struct hash for RemoveChangeIntent
    struct_hash = get_remove_change_intent_struct_hash(pq_fingerprint, eth_nonce)
    
    # Get the domain separator (use the hardcoded one from config)
    domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    
    # Create the EIP-712 digest
    digest = keccak(b'\x19\x01' + domain_separator + struct_hash)
    
    # Sign the digest
    signature = sign_eip712_message(digest, private_key)
    
    # DEBUG: Print all the values for debugging
    print(f"DEBUG: pq_fingerprint: {pq_fingerprint}")
    print(f"DEBUG: eth_nonce: {eth_nonce}")
    print(f"DEBUG: struct_hash: {struct_hash.hex()}")
    print(f"DEBUG: domain_separator: {domain_separator.hex()}")
    print(f"DEBUG: digest: {digest.hex()}")
    print(f"DEBUG: signature v: {signature['v']}")
    print(f"DEBUG: signature r: {hex(signature['r'])}")
    print(f"DEBUG: signature s: {hex(signature['s'])}")
    
    # Convert r and s to hex strings to match expected format
    return {
        "v": signature["v"],
        "r": hex(signature["r"]),
        "s": hex(signature["s"])
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

        # Create the ETH cancel message for parsing (not for signing)
        eth_message = create_eth_cancel_change_eth_address_message(pq_fingerprint, eth_nonce)
        
        # Sign using EIP-712 standards
        eth_signature = sign_eth_message_eip712(pq_fingerprint, eth_nonce, eth_private_key)
        
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
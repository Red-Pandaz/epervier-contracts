#!/usr/bin/env python3

import json
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'vector_generators', 'common'))

from common_utils import *
from message_builder import *

def generate_bob_registration_intent():
    """Generate Bob's registration intent with BobETH nonce 1 and BobPQ nonce 0"""
    
    # Load test data
    with open("test/python/vector_generators/common/test_data.json", "r") as f:
        test_data = json.load(f)
    
    bob = test_data["bob"]
    
    # Bob's nonces
    bob_eth_nonce = 1  # Bob used nonce 0 for change intent, so this is 1
    bob_pq_nonce = 0   # First registration attempt
    
    print(f"Generating Bob's registration intent:")
    print(f"  Bob ETH address: {bob['eth_address']}")
    print(f"  Bob PQ fingerprint: {bob['pq_fingerprint']}")
    print(f"  Bob ETH nonce: {bob_eth_nonce}")
    print(f"  Bob PQ nonce: {bob_pq_nonce}")
    
    # --- EXACT SAME LOGIC AS registration_intent_generator.py ---
    # Build base PQ message for Bob's registration intent
    bob_base_pq_message = build_base_pq_message(DOMAIN_SEPARATOR, bob["eth_address"], bob_pq_nonce)
    
    # PQ sign the base message
    bob_pq_sig = sign_with_pq_key(bob_base_pq_message, bob["pq_private_key_file"])
    
    # Build ETH intent message (contains nested PQ signature and base PQ message)
    bob_eth_message = build_eth_intent_message(
        bob_base_pq_message,
        bob_pq_sig["salt"],
        bob_pq_sig["cs1"],
        bob_pq_sig["cs2"],
        bob_pq_sig["hint"],
        bob_eth_nonce
    )
    
    # ETH sign the ETH intent message
    bob_eth_sig = sign_with_eth_key(bob_eth_message, bob["eth_private_key_file"])
    
    # Build the final PQ message (contains nested ETH signature and ETH message)
    bob_pq_message = build_pq_intent_message(
        DOMAIN_SEPARATOR,
        bob["eth_address"],
        bob_eth_message,
        bob_eth_sig["v"],
        bob_eth_sig["r"],
        bob_eth_sig["s"],
        bob_pq_nonce
    )
    
    # PQ sign the final PQ message
    bob_final_pq_sig = sign_with_pq_key(bob_pq_message, bob["pq_private_key_file"])
    
    # Create the vector
    bob_registration_intent = {
        "actor": "bob",
        "eth_address": bob["eth_address"],
        "pq_fingerprint": bob["pq_fingerprint"],
        "base_pq_message": bob_base_pq_message.hex(),
        "pq_signature": {
            "salt": bob_pq_sig["salt"].hex(),
            "cs1": [hex(x) for x in bob_pq_sig["cs1"]],
            "cs2": [hex(x) for x in bob_pq_sig["cs2"]],
            "hint": bob_pq_sig["hint"]
        },
        "eth_message": bob_eth_message.hex(),
        "eth_signature": {
            "v": bob_eth_sig["v"],
            "r": bob_eth_sig["r"],
            "s": bob_eth_sig["s"]
        },
        "eth_nonce": bob_eth_nonce
    }
    
    # Save to file
    output = {
        "bob_registration_intent": bob_registration_intent
    }
    
    with open("test/test_vectors/revert/bob_registration_intent.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nGenerated Bob's registration intent vector:")
    print(f"  ETH message length: {len(bob_eth_message)} bytes")
    print(f"  PQ message length: {len(bob_pq_message)} bytes")
    print(f"  Saved to: test/test_vectors/revert/bob_registration_intent.json")

if __name__ == "__main__":
    generate_bob_registration_intent() 
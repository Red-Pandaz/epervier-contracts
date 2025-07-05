#!/usr/bin/env python3
"""
Generate test vectors for the scenario where Alice has a change ETH intent pending (AlicePQ -> BobETH),
and Bob tries to submit a registration intent which should revert.
"""

import json
import sys
import os
from pathlib import Path

# Add the vector generators directory to the path
sys.path.append(str(Path(__file__).parent / "vector_generators" / "advanced"))

from consolidated_advanced_vector_generator import AdvancedVectorGenerator, DOMAIN_SEPARATOR
from eth_account import Account
import secrets

def generate_change_intent_blocking_registration_vectors():
    """Generate test vectors for the change intent blocking registration scenario"""
    
    generator = AdvancedVectorGenerator()
    
    # Step 1: Alice's registration (AliceETH and AlicePQ)
    alice_registration = generator.generate_registration_intent_vector("alice", eth_nonce=0, pq_nonce=0)
    alice_confirmation = generator.generate_registration_confirmation_vector("alice", eth_nonce=0, pq_nonce=0)
    
    # Step 2: Alice's change ETH intent (AlicePQ -> BobETH)
    alice_change_intent = generator.generate_change_eth_address_intent_vector(
        "alice", 
        generator.actors["bob"]["eth_address"], 
        eth_nonce=1, 
        pq_nonce=1
    )
    
    # Step 3: Bob's registration attempt (should revert)
    bob_registration_attempt = generator.generate_registration_intent_vector("bob", eth_nonce=0, pq_nonce=0)
    
    # Create the test vector structure
    test_vectors = {
        "alice_registration": {
            "eth_message": alice_registration["eth_message"],
            "pq_message": alice_registration["pq_message"],
            "eth_signature": alice_registration["eth_signature"],
            "pq_signature": alice_registration["pq_signature"],
            "confirm_message": alice_confirmation["pq_message"],
            "confirm_signature": alice_confirmation["pq_signature"]
        },
        "alice_change_intent": {
            "eth_message": alice_change_intent["eth_message"],
            "pq_message": alice_change_intent["pq_message"],
            "eth_signature": alice_change_intent["eth_signature"],
            "pq_signature": alice_change_intent["pq_signature"]
        },
        "bob_registration_attempt": {
            "eth_message": bob_registration_attempt["eth_message"],
            "pq_message": bob_registration_attempt["pq_message"],
            "eth_signature": bob_registration_attempt["eth_signature"],
            "pq_signature": bob_registration_attempt["pq_signature"]
        }
    }
    
    # Save the test vectors
    output_path = Path("test/test_vectors/revert")
    output_path.mkdir(parents=True, exist_ok=True)
    
    with open(output_path / "change_intent_blocking_registration_revert_vectors.json", "w") as f:
        json.dump(test_vectors, f, indent=2)
    
    print("Generated change_intent_blocking_registration_revert_vectors.json")

if __name__ == "__main__":
    generate_change_intent_blocking_registration_vectors() 
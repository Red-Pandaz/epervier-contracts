#!/usr/bin/env python3
"""
Generate correct advanced vectors for the test scenario:
ETH Registration - PQ Removes - ETH Retries - PQ Confirms
"""

import json
import os
from advanced_vector_generator import AdvancedVectorGenerator

def main():
    """Generate the correct advanced vectors for the test"""
    generator = AdvancedVectorGenerator()
    
    print("Generating correct advanced vectors for test scenario...")
    
    # Generate vectors for the specific test scenario
    vectors = {
        "registration_intent_nonce2": [
            generator.generate_registration_intent_vector("alice", 1, 2)  # ETH nonce 1, PQ nonce 2
        ],
        "registration_confirmation_nonce3": [
            generator.generate_registration_confirmation_vector("alice", 2, 3)  # ETH nonce 2, PQ nonce 3
        ]
    }
    
    # Save to the correct file
    output_file = "test/test_vectors/advanced/correct_advanced_vectors.json"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(vectors, f, indent=2)
    
    print(f"Generated vectors:")
    print(f"  registration_intent_nonce2[0]: ETH nonce {vectors['registration_intent_nonce2'][0]['eth_nonce']}, PQ nonce {vectors['registration_intent_nonce2'][0]['pq_nonce']}")
    print(f"  registration_confirmation_nonce3[0]: ETH nonce {vectors['registration_confirmation_nonce3'][0]['eth_nonce']}, PQ nonce {vectors['registration_confirmation_nonce3'][0]['pq_nonce']}")
    print(f"Saved to: {output_file}")

if __name__ == "__main__":
    main() 
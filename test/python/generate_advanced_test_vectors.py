#!/usr/bin/env python3
"""
Generate specific vectors for the advanced test that's failing

The test needs:
1. Registration intent with nonce 0 (already exists)
2. PQ removal with nonce 1 (already exists)
3. Registration intent with nonce 2 (missing)
4. Registration confirmation with nonce 3 (missing)
"""

import json
import os
import sys
from typing import Dict, List, Any

# Import the advanced vector generator
from advanced_vector_generator import AdvancedVectorGenerator

def generate_missing_vectors():
    """Generate the missing vectors for the advanced test"""
    generator = AdvancedVectorGenerator()
    
    # Generate vectors for Alice (the actor used in the test)
    actor = "alice"
    
    print("Generating missing vectors for advanced test...")
    
    # Step 3: Registration intent with nonce 2
    print("Generating registration intent with nonce 2...")
    intent_nonce2 = generator.generate_registration_intent_vector(actor, 2, 2)
    
    # Step 4: Registration confirmation with nonce 3
    print("Generating registration confirmation with nonce 3...")
    confirm_nonce3 = generator.generate_registration_confirmation_vector(actor, 3, 3)
    
    # Create the output structure
    output = {
        "registration_intent_nonce2": [intent_nonce2],
        "registration_confirmation_nonce3": [confirm_nonce3]
    }
    
    # Save to file
    output_file = "test/test_vectors/advanced/missing_vectors.json"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"Generated vectors saved to: {output_file}")
    print(f"Registration intent nonce 2: {intent_nonce2['eth_nonce']}")
    print(f"Registration confirmation nonce 3: {confirm_nonce3['pq_nonce']}")
    
    return output

if __name__ == "__main__":
    generate_missing_vectors() 
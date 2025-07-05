#!/usr/bin/env python3
"""
Convert working generator output to expected test format

The working generator creates files with a 'vectors' array structure,
but the tests expect specific JSON paths like '.removal_change_pq[0].message'
"""

import json
import sys
from pathlib import Path

def convert_test4_format():
    """Convert test4_pq_cancels_change_eth_vectors.json to expected format"""
    
    # Read the working generator's output
    working_file = Path("../../../test_vectors/advanced/test4_pq_cancels_change_eth_vectors.json")
    if not working_file.exists():
        print(f"Error: {working_file} not found")
        return
    
    with open(working_file, 'r') as f:
        data = json.load(f)
    
    # Extract the removal vector (index 3 in the working format)
    if len(data["vectors"]) < 4:
        print("Error: Not enough vectors in working file")
        return
    
    removal_vector = data["vectors"][3]  # Step 3: PQ cancels change intent
    
    # Create the expected format
    expected_format = {
        "removal_change_pq": [
            {
                "message": removal_vector["pq_message"],
                "signature": {
                    "salt": removal_vector["pq_signature"]["salt"],
                    "cs1": removal_vector["pq_signature"]["cs1"],
                    "cs2": removal_vector["pq_signature"]["cs2"],
                    "hint": removal_vector["pq_signature"]["hint"]
                },
                "pq_nonce": removal_vector["pq_nonce"]
            }
        ]
    }
    
    # Write the converted format
    output_file = Path("../../../test_vectors/advanced/test4_pq_cancels_change_eth_removal_change_pq_vectors.json")
    with open(output_file, 'w') as f:
        json.dump(expected_format, f, indent=2)
    
    print(f"Converted test4 removal vector to: {output_file}")

def convert_test5_format():
    """Convert test5_eth_cancels_change_eth_vectors.json to expected format"""
    
    # Read the working generator's output
    working_file = Path("../../../test_vectors/advanced/test5_eth_cancels_change_eth_vectors.json")
    if not working_file.exists():
        print(f"Error: {working_file} not found")
        return
    
    with open(working_file, 'r') as f:
        data = json.load(f)
    
    # Extract the removal vector (index 3 in the working format)
    if len(data["vectors"]) < 4:
        print("Error: Not enough vectors in working file")
        return
    
    removal_vector = data["vectors"][3]  # Step 3: ETH cancels change intent
    
    # Create the expected format
    expected_format = {
        "removal_change_eth": [
            {
                "message": removal_vector["eth_message"],
                "signature": {
                    "v": removal_vector["eth_signature"]["v"],
                    "r": removal_vector["eth_signature"]["r"],
                    "s": removal_vector["eth_signature"]["s"]
                },
                "eth_nonce": removal_vector["eth_nonce"]
            }
        ]
    }
    
    # Write the converted format
    output_file = Path("../../../test_vectors/advanced/test5_eth_cancels_change_eth_removal_change_eth_vectors.json")
    with open(output_file, 'w') as f:
        json.dump(expected_format, f, indent=2)
    
    print(f"Converted test5 removal vector to: {output_file}")

def main():
    """Convert all working generator outputs to expected format"""
    print("Converting working generator output to expected test format...")
    
    convert_test4_format()
    convert_test5_format()
    
    print("Conversion complete!")

if __name__ == "__main__":
    main() 
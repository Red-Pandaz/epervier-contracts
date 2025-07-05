#!/usr/bin/env python3
"""
Generate missing confirmation revert test vectors for PQRegistry tests.
"""

import json
import os
from pathlib import Path

def generate_missing_confirm_revert_vectors():
    """Generate missing confirmation revert test vectors."""
    
    # Base directory
    base_dir = Path(__file__).parent.parent
    
    # Read existing vectors
    vectors_file = base_dir.parent.parent / "test_vectors" / "revert" / "confirm_registration_revert_vectors.json"
    
    with open(vectors_file, 'r') as f:
        data = json.load(f)
    
    existing_tests = [test["test_name"] for test in data["confirm_registration_reverts"]]
    print(f"Existing tests: {existing_tests}")
    
    # Define missing test vectors
    missing_tests = [
        {
            "test_name": "wrong_message_format",
            "description": "Test revert when PQ confirmation message has wrong format",
            "eth_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "pq_fingerprint": "0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb",
            "pq_nonce": 1,
            "pq_message": "07668882b5c3598c149b213b1c16ab1dd94b45bc4837b468e006b97caef5df92wrong message format for confirmation",
            "pq_signature": {
                "salt": "9f367c6ffc597bd675d4ace413b68f9c11b31ee5ff17b74d625c1125ccb6898528dce178ba4f8306",
                "cs1": ["0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"] * 32,
                "cs2": ["0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"] * 32,
                "hint": 1000
            }
        },
        {
            "test_name": "invalid_eth_signature",
            "description": "Test revert when ETH signature in PQ message is invalid",
            "eth_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "pq_fingerprint": "0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb",
            "pq_nonce": 1,
            "pq_message": "07668882b5c3598c149b213b1c16ab1dd94b45bc4837b468e006b97caef5df92Confirm registration with ETH Address 0x1234567890123456789012345678901234567890",
            "pq_signature": {
                "salt": "9f367c6ffc597bd675d4ace413b68f9c11b31ee5ff17b74d625c1125ccb6898528dce178ba4f8306",
                "cs1": ["0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"] * 32,
                "cs2": ["0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"] * 32,
                "hint": 1000
            }
        },
        {
            "test_name": "wrong_eth_nonce",
            "description": "Test revert when ETH nonce in PQ message is wrong",
            "eth_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "pq_fingerprint": "0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb",
            "pq_nonce": 1,
            "pq_message": "07668882b5c3598c149b213b1c16ab1dd94b45bc4837b468e006b97caef5df92Confirm registration with ETH Address 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "pq_signature": {
                "salt": "9f367c6ffc597bd675d4ace413b68f9c11b31ee5ff17b74d625c1125ccb6898528dce178ba4f8306",
                "cs1": ["0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"] * 32,
                "cs2": ["0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"] * 32,
                "hint": 1000
            }
        },
        {
            "test_name": "eth_address_mismatch",
            "description": "Test revert when ETH address in PQ message doesn't match recovered ETH signature",
            "eth_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "pq_fingerprint": "0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb",
            "pq_nonce": 1,
            "pq_message": "07668882b5c3598c149b213b1c16ab1dd94b45bc4837b468e006b97caef5df92Confirm registration with ETH Address 0x1234567890123456789012345678901234567890",
            "pq_signature": {
                "salt": "9f367c6ffc597bd675d4ace413b68f9c11b31ee5ff17b74d625c1125ccb6898528dce178ba4f8306",
                "cs1": ["0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"] * 32,
                "cs2": ["0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"] * 32,
                "hint": 1000
            }
        },
        {
            "test_name": "pq_fingerprint_mismatch",
            "description": "Test revert when PQ fingerprint in ETH signature doesn't match recovered PQ signature",
            "eth_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "pq_fingerprint": "0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb",
            "pq_nonce": 1,
            "pq_message": "07668882b5c3598c149b213b1c16ab1dd94b45bc4837b468e006b97caef5df92Confirm registration with ETH Address 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "pq_signature": {
                "salt": "9f367c6ffc597bd675d4ace413b68f9c11b31ee5ff17b74d625c1125ccb6898528dce178ba4f8306",
                "cs1": ["0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"] * 32,
                "cs2": ["0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"] * 32,
                "hint": 1000
            }
        },
        {
            "test_name": "malformed_message",
            "description": "Test revert when PQ confirmation message is malformed (too short)",
            "eth_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "pq_fingerprint": "0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb",
            "pq_nonce": 1,
            "pq_message": "short",
            "pq_signature": {
                "salt": "9f367c6ffc597bd675d4ace413b68f9c11b31ee5ff17b74d625c1125ccb6898528dce178ba4f8306",
                "cs1": ["0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"] * 32,
                "cs2": ["0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"] * 32,
                "hint": 1000
            }
        }
    ]
    
    # Add missing tests
    for test in missing_tests:
        if test["test_name"] not in existing_tests:
            data["confirm_registration_reverts"].append(test)
            print(f"Added test: {test['test_name']}")
    
    # Write updated vectors
    with open(vectors_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Updated {vectors_file}")
    print(f"Total tests: {len(data['confirm_registration_reverts'])}")
    
    return data

def main():
    """Generate missing confirm revert vectors and write to expected output file."""
    # Generate the vectors
    data = generate_missing_confirm_revert_vectors()
    
    # Write to the expected output file
    base_dir = Path(__file__).parent.parent
    output_file = base_dir.parent.parent / "test_vectors" / "revert" / "missing_confirm_revert_vectors.json"
    
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Written to: {output_file}")

if __name__ == "__main__":
    main() 
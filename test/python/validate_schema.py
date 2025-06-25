#!/usr/bin/env python3
"""
Simple Schema Validation for PQRegistry Test Vectors
"""

import json
import sys
from pathlib import Path

def load_schema():
    """Load the message schema."""
    schema_path = Path("../pqregistry_message_schema.json")
    with open(schema_path, 'r') as f:
        return json.load(f)

def load_test_vector():
    """Load the test vector."""
    vector_path = Path("test_vectors/alice_test_vector.json")
    with open(vector_path, 'r') as f:
        return json.load(f)

def hex_to_bytes(hex_str):
    """Convert hex string to bytes."""
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)

def analyze_message_structure(message_bytes, message_name):
    """Analyze the structure of a message to understand its format."""
    print(f"\n=== {message_name} Analysis ===")
    print(f"Total length: {len(message_bytes)} bytes")
    
    if len(message_bytes) >= 32:
        domain_separator = message_bytes[:32]
        print(f"Domain separator: {domain_separator.hex()}")
        
        # For the remove intent message, we know the structure:
        # DOMAIN_SEPARATOR (32) + pattern + pqFingerprint (20) + ethNonce (32)
        remaining = message_bytes[32:]
        
        # The pattern is everything before the last 52 bytes (20 for address + 32 for nonce)
        if len(remaining) >= 52:
            pattern = remaining[:-52]
            pq_fingerprint = remaining[-52:-32]
            eth_nonce = remaining[-32:]
            
            try:
                pattern_str = pattern.decode('utf-8')
                print(f"Pattern: \"{pattern_str}\" ({len(pattern)} bytes)")
                print(f"PQ Fingerprint: {pq_fingerprint.hex()}")
                print(f"ETH Nonce: {int.from_bytes(eth_nonce, 'big')}")
            except UnicodeDecodeError:
                print(f"Pattern: {pattern.hex()} ({len(pattern)} bytes) - not valid UTF-8")
                print(f"PQ Fingerprint: {pq_fingerprint.hex()}")
                print(f"ETH Nonce: {int.from_bytes(eth_nonce, 'big')}")
        else:
            print(f"Message too short to contain expected structure")

def main():
    print("=== PQRegistry Schema Validation ===")
    
    try:
        schema = load_schema()
        test_vector = load_test_vector()
        print("✅ Files loaded successfully")
    except Exception as e:
        print(f"❌ Error loading files: {e}")
        return
    
    print("\n=== Checking Message Lengths ===")
    
    # Check BasePQRegistrationIntentMessage
    base_pq_message = hex_to_bytes(test_vector["registration"]["base_pq_message"])
    expected_length = schema["BasePQRegistrationIntentMessage"]["total_length"]
    actual_length = len(base_pq_message)
    print(f"BasePQRegistrationIntentMessage: {actual_length} bytes (expected {expected_length})")
    if actual_length == expected_length:
        print("✅ Length matches schema")
    else:
        print("❌ Length mismatch with schema")
    
    # Check ETHRegistrationIntentMessage
    eth_intent_message = hex_to_bytes(test_vector["registration"]["eth_intent_message"])
    expected_length = schema["ETHRegistrationIntentMessage"]["total_length"]
    actual_length = len(eth_intent_message)
    print(f"ETHRegistrationIntentMessage: {actual_length} bytes (expected {expected_length})")
    if actual_length == expected_length:
        print("✅ Length matches schema")
    else:
        print("❌ Length mismatch with schema")
    
    # Check PQRegistrationConfirmationMessage
    pq_confirm_message = hex_to_bytes(test_vector["registration"]["pq_confirm_message"])
    expected_length = schema["PQRegistrationConfirmationMessage"]["total_length"]
    actual_length = len(pq_confirm_message)
    print(f"PQRegistrationConfirmationMessage: {actual_length} bytes (expected {expected_length})")
    if actual_length == expected_length:
        print("✅ Length matches schema")
    else:
        print("❌ Length mismatch with schema")
    
    # Check ETHRemoveRegistrationIntentMessage
    remove_intent_message = hex_to_bytes(test_vector["remove_intent"]["registration"]["eth_message"])
    expected_length = schema["ETHRemoveRegistrationIntentMessage"]["total_length"]
    actual_length = len(remove_intent_message)
    print(f"ETHRemoveRegistrationIntentMessage: {actual_length} bytes (expected {expected_length})")
    if actual_length == expected_length:
        print("✅ Length matches schema")
    else:
        print("❌ Length mismatch with schema")
        analyze_message_structure(remove_intent_message, "ETHRemoveRegistrationIntentMessage")
        
        # Show what the schema expects
        schema_pattern = schema["ETHRemoveRegistrationIntentMessage"]["fields"][1]["value"]
        schema_pattern_length = schema["ETHRemoveRegistrationIntentMessage"]["fields"][1]["length"]
        print(f"\nSchema expects pattern: \"{schema_pattern}\" ({schema_pattern_length} bytes)")
        print(f"Schema total length breakdown:")
        for field in schema["ETHRemoveRegistrationIntentMessage"]["fields"]:
            print(f"  {field['name']}: {field['length']} bytes")
    
    print("\n=== Schema Validation Complete ===")

if __name__ == "__main__":
    main()
 
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
    vector_path = Path("test_vectors/comprehensive_vector_1.json")
    with open(vector_path, 'r') as f:
        return json.load(f)

def hex_to_bytes(hex_str):
    """Convert hex string to bytes."""
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)

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
    
    # Check ETHRegistrationIntentMessage
    eth_intent_message = hex_to_bytes(test_vector["registration"]["eth_intent_message"])
    expected_length = schema["ETHRegistrationIntentMessage"]["total_length"]
    actual_length = len(eth_intent_message)
    print(f"ETHRegistrationIntentMessage: {actual_length} bytes (expected {expected_length})")
    
    # Check PQRegistrationConfirmationMessage
    pq_confirm_message = hex_to_bytes(test_vector["registration"]["pq_confirm_message"])
    expected_length = schema["PQRegistrationConfirmationMessage"]["total_length"]
    actual_length = len(pq_confirm_message)
    print(f"PQRegistrationConfirmationMessage: {actual_length} bytes (expected {expected_length})")
    
    # Check ETHRemoveIntentMessage
    remove_intent_message = hex_to_bytes(test_vector["remove_intent"]["eth_message"])
    expected_length = schema["ETHRemoveIntentMessage"]["total_length"]
    actual_length = len(remove_intent_message)
    print(f"ETHRemoveIntentMessage: {actual_length} bytes (expected {expected_length})")
    
    print("\n=== Schema Validation Complete ===")

if __name__ == "__main__":
    main()

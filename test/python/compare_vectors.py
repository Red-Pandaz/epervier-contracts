#!/usr/bin/env python3
"""
Compare passing vectors with failing advanced vectors and validate against schema
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any

def load_schema():
    """Load the message schema."""
    schema_path = Path("../../preregistry_message_schema.json")
    with open(schema_path, 'r') as f:
        return json.load(f)

def hex_to_bytes(hex_str):
    """Convert hex string to bytes."""
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)

def analyze_message_structure(message_bytes, message_name, schema_info=None):
    """Analyze the structure of a message to understand its format."""
    print(f"\n=== {message_name} Analysis ===")
    print(f"Total length: {len(message_bytes)} bytes")
    
    if len(message_bytes) >= 32:
        domain_separator = message_bytes[:32]
        print(f"Domain separator: {domain_separator.hex()}")
        
        remaining = message_bytes[32:]
        
        if schema_info and "fields" in schema_info:
            print(f"Schema expects: {schema_info['total_length']} bytes")
            print("Schema field breakdown:")
            for field in schema_info["fields"]:
                print(f"  {field['name']}: {field['length']} bytes")
                if "value" in field:
                    print(f"    Expected value: \"{field['value']}\"")
        
        # Try to decode as UTF-8 to see if it's a string pattern
        try:
            pattern_str = remaining.decode('utf-8')
            print(f"Remaining content as string: \"{pattern_str}\"")
        except UnicodeDecodeError:
            print(f"Remaining content as hex: {remaining.hex()}")
    
    return len(message_bytes)

def validate_message_length(message_bytes, schema_info, message_name):
    """Validate message length against schema."""
    expected_length = schema_info["total_length"]
    actual_length = len(message_bytes)
    
    print(f"{message_name}: {actual_length} bytes (expected {expected_length})")
    if actual_length == expected_length:
        print("✅ Length matches schema")
        return True
    else:
        print(f"❌ Length mismatch with schema (diff: {actual_length - expected_length})")
        return False

def analyze_vector_file(file_path: Path, schema: Dict, file_type: str):
    """Analyze a vector file and validate against schema."""
    print(f"\n{'='*60}")
    print(f"ANALYZING {file_type.upper()}: {file_path.name}")
    print(f"{'='*60}")
    
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Error loading {file_path}: {e}")
        return
    
    # Get the first key (usually the flow type)
    if not data:
        print("❌ Empty file")
        return
    
    flow_key = list(data.keys())[0]
    vectors = data[flow_key]
    
    if not vectors:
        print("❌ No vectors found")
        return
    
    print(f"Found {len(vectors)} vectors in {flow_key}")
    
    # Analyze first few vectors
    for i, vector in enumerate(vectors[:3]):  # Look at first 3 vectors
        print(f"\n--- Vector {i+1} ---")
        
        # Check for different message types
        message_types = []
        
        if "eth_message" in vector and vector["eth_message"]:
            message_types.append(("eth_message", vector["eth_message"]))
        
        if "pq_message" in vector and vector["pq_message"]:
            message_types.append(("pq_message", vector["pq_message"]))
        
        if "base_pq_message" in vector and vector["base_pq_message"]:
            message_types.append(("base_pq_message", vector["base_pq_message"]))
        
        if "base_eth_message" in vector and vector["base_eth_message"]:
            message_types.append(("base_eth_message", vector["base_eth_message"]))
        
        for msg_type, msg_hex in message_types:
            if not msg_hex:
                continue
                
            try:
                msg_bytes = hex_to_bytes(msg_hex)
                
                # Try to match against schema based on message content
                schema_match = None
                for schema_name, schema_info in schema.items():
                    if "fields" in schema_info and len(schema_info["fields"]) > 0:
                        first_field = schema_info["fields"][0]
                        if "value" in first_field:
                            expected_pattern = first_field["value"]
                            # Look for the pattern in the message after domain separator
                            if len(msg_bytes) >= 32 + len(expected_pattern):
                                try:
                                    actual_pattern = msg_bytes[32:32+len(expected_pattern)].decode('utf-8')
                                    if actual_pattern == expected_pattern:
                                        schema_match = (schema_name, schema_info)
                                        break
                                except UnicodeDecodeError:
                                    continue
                
                if schema_match:
                    schema_name, schema_info = schema_match
                    print(f"\n{msg_type} matches schema: {schema_name}")
                    validate_message_length(msg_bytes, schema_info, msg_type)
                    analyze_message_structure(msg_bytes, f"{msg_type} ({schema_name})", schema_info)
                else:
                    print(f"\n{msg_type} - no schema match found")
                    analyze_message_structure(msg_bytes, msg_type)
                    
            except Exception as e:
                print(f"❌ Error analyzing {msg_type}: {e}")

def main():
    print("=== PQRegistry Vector Comparison and Schema Validation ===")
    
    try:
        schema = load_schema()
        print("✅ Schema loaded successfully")
    except Exception as e:
        print(f"❌ Error loading schema: {e}")
        return
    
    # Define paths
    passing_dir = Path("../test_vectors")
    failing_dir = Path("../test_vectors/advanced")
    
    # Analyze passing vectors
    print(f"\n{'='*60}")
    print("ANALYZING PASSING VECTORS")
    print(f"{'='*60}")
    
    passing_files = [
        "registration_intent_vectors.json",
        "registration_confirmation_vectors.json",
        "registration_eth_removal_vectors.json",
        "registration_pq_removal_vectors.json"
    ]
    
    for filename in passing_files:
        file_path = passing_dir / filename
        if file_path.exists():
            analyze_vector_file(file_path, schema, "PASSING")
        else:
            print(f"⚠️  Passing file not found: {file_path}")
    
    # Analyze failing vectors
    print(f"\n{'='*60}")
    print("ANALYZING FAILING ADVANCED VECTORS")
    print(f"{'='*60}")
    
    failing_files = [
        "registration_flow_with_removal_vectors.json",
        "change_eth_flow_with_cancellation_vectors.json",
        "unregistration_flow_with_revocation_vectors.json"
    ]
    
    for filename in failing_files:
        file_path = failing_dir / filename
        if file_path.exists():
            analyze_vector_file(file_path, schema, "FAILING")
        else:
            print(f"⚠️  Failing file not found: {file_path}")
    
    print(f"\n{'='*60}")
    print("COMPARISON COMPLETE")
    print(f"{'='*60}")

if __name__ == "__main__":
    main() 
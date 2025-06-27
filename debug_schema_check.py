#!/usr/bin/env python3
import json
import binascii

def hex_to_bytes(hex_str):
    """Convert hex string to bytes"""
    if hex_str.startswith('0x'):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)

def analyze_eth_message(eth_message_hex):
    """Analyze ETH message structure against schema"""
    print("=== ETH Message Analysis ===")
    eth_message = hex_to_bytes(eth_message_hex)
    print(f"Total length: {len(eth_message)} bytes")
    
    # Expected structure from schema:
    # DOMAIN_SEPARATOR (32) + pattern (49) + pqFingerprint (20) + basePQMessage (112) + salt (40) + cs1 (1024) + cs2 (1024) + hint (32) + ethNonce (32)
    # Total: 2408 bytes
    
    if len(eth_message) != 2408:
        print(f"❌ ERROR: Expected 2408 bytes, got {len(eth_message)}")
        print(f"Missing: {2408 - len(eth_message)} bytes")
    
    # Check DOMAIN_SEPARATOR (first 32 bytes)
    domain_separator = eth_message[:32]
    print(f"DOMAIN_SEPARATOR: {domain_separator.hex()}")
    
    # Check pattern (next 49 bytes)
    pattern_start = 32
    pattern_end = 32 + 49
    if pattern_end <= len(eth_message):
        pattern = eth_message[pattern_start:pattern_end]
        expected_pattern = b"Confirm unregistration from Epervier Fingerprint "
        print(f"Pattern: {pattern}")
        print(f"Expected: {expected_pattern}")
        if pattern == expected_pattern:
            print("✅ Pattern matches")
        else:
            print("❌ Pattern mismatch")
            return False
    else:
        print("❌ Message too short for pattern")
        return False
    
    # Check pqFingerprint (next 20 bytes)
    fingerprint_start = 32 + 49
    fingerprint_end = fingerprint_start + 20
    if fingerprint_end <= len(eth_message):
        fingerprint = eth_message[fingerprint_start:fingerprint_end]
        print(f"PQ Fingerprint: 0x{fingerprint.hex()}")
    else:
        print("❌ Message too short for fingerprint")
        return False
    
    # Check basePQMessage (next 112 bytes)
    base_pq_start = fingerprint_end
    base_pq_end = base_pq_start + 112
    if base_pq_end <= len(eth_message):
        base_pq_message = eth_message[base_pq_start:base_pq_end]
        print(f"Base PQ Message length: {len(base_pq_message)} bytes")
        
        # Analyze basePQMessage structure
        print("\n=== Base PQ Message Analysis ===")
        # Expected: DOMAIN_SEPARATOR (32) + pattern (40) + ethAddress (20) + pqNonce (32)
        if len(base_pq_message) != 112:
            print(f"❌ ERROR: Base PQ message should be 112 bytes, got {len(base_pq_message)}")
            return False
        
        # Check base PQ pattern
        base_pattern_start = 32
        base_pattern_end = 32 + 40
        base_pattern = base_pq_message[base_pattern_start:base_pattern_end]
        expected_base_pattern = b"Confirm unregistration from ETH Address "
        print(f"Base Pattern: {base_pattern}")
        print(f"Expected: {expected_base_pattern}")
        if base_pattern == expected_base_pattern:
            print("✅ Base pattern matches")
        else:
            print("❌ Base pattern mismatch")
            return False
        
        # Check ethAddress in base message
        eth_addr_start = 32 + 40
        eth_addr_end = eth_addr_start + 20
        eth_address = base_pq_message[eth_addr_start:eth_addr_end]
        print(f"ETH Address in base message: 0x{eth_address.hex()}")
        
        # Check pqNonce in base message
        pq_nonce_start = eth_addr_end
        pq_nonce_end = pq_nonce_start + 32
        pq_nonce = base_pq_message[pq_nonce_start:pq_nonce_end]
        print(f"PQ Nonce in base message: {int.from_bytes(pq_nonce, 'big')}")
    else:
        print("❌ Message too short for base PQ message")
        return False
    
    # Check remaining components
    salt_start = base_pq_end
    salt_end = salt_start + 40
    if salt_end <= len(eth_message):
        salt = eth_message[salt_start:salt_end]
        print(f"Salt length: {len(salt)} bytes")
    else:
        print("❌ Message too short for salt")
        return False
    
    cs1_start = salt_end
    cs1_end = cs1_start + 1024
    if cs1_end <= len(eth_message):
        cs1 = eth_message[cs1_start:cs1_end]
        print(f"CS1 length: {len(cs1)} bytes")
    else:
        print("❌ Message too short for cs1")
        return False
    
    cs2_start = cs1_end
    cs2_end = cs2_start + 1024
    if cs2_end <= len(eth_message):
        cs2 = eth_message[cs2_start:cs2_end]
        print(f"CS2 length: {len(cs2)} bytes")
    else:
        print("❌ Message too short for cs2")
        return False
    
    hint_start = cs2_end
    hint_end = hint_start + 32
    if hint_end <= len(eth_message):
        hint = eth_message[hint_start:hint_end]
        print(f"Hint: {int.from_bytes(hint, 'big')}")
    else:
        print("❌ Message too short for hint")
        return False
    
    eth_nonce_start = hint_end
    eth_nonce_end = eth_nonce_start + 32
    if eth_nonce_end <= len(eth_message):
        eth_nonce = eth_message[eth_nonce_start:eth_nonce_end]
        print(f"ETH Nonce: {int.from_bytes(eth_nonce, 'big')}")
    else:
        print("❌ Message too short for ETH nonce")
        print(f"Message ends at byte {len(eth_message)}, need {eth_nonce_end}")
        return False
    
    return True

def analyze_actual_structure(eth_message_hex):
    """Analyze the actual structure to see what's there"""
    print("\n=== ACTUAL STRUCTURE ANALYSIS ===")
    eth_message = hex_to_bytes(eth_message_hex)
    
    # Let's see what's at the end
    print(f"Last 50 bytes: {eth_message[-50:].hex()}")
    
    # Check if the pattern is correct
    pattern_start = 32
    pattern_end = 32 + 49
    if pattern_end <= len(eth_message):
        pattern = eth_message[pattern_start:pattern_end]
        print(f"Pattern at offset 32: {pattern}")
    
    # Check the base PQ message pattern
    fingerprint_start = 32 + 49
    fingerprint_end = fingerprint_start + 20
    base_pq_start = fingerprint_end
    base_pq_end = base_pq_start + 112
    
    if base_pq_end <= len(eth_message):
        base_pq_message = eth_message[base_pq_start:base_pq_end]
        base_pattern_start = 32
        base_pattern_end = 32 + 40
        if base_pattern_end <= len(base_pq_message):
            base_pattern = base_pq_message[base_pattern_start:base_pattern_end]
            print(f"Base pattern: {base_pattern}")
    
    # Let's see what's missing by checking the end
    expected_end = 2408
    actual_end = len(eth_message)
    missing_bytes = expected_end - actual_end
    
    print(f"Expected end: {expected_end}")
    print(f"Actual end: {actual_end}")
    print(f"Missing: {missing_bytes} bytes")
    
    # Check what should be at the end according to schema
    if missing_bytes > 0:
        print(f"According to schema, the last {missing_bytes} bytes should be:")
        if missing_bytes == 32:
            print("  - ETH nonce (32 bytes)")
        elif missing_bytes == 64:
            print("  - Hint (32 bytes) + ETH nonce (32 bytes)")
        else:
            print(f"  - Unknown: {missing_bytes} bytes")

def main():
    # Load the test vectors
    with open('test/test_vectors/unregistration_confirmation_vectors.json', 'r') as f:
        data = json.load(f)
    
    print("Analyzing unregistration confirmation vectors against schema...")
    print("=" * 60)
    
    # Just analyze the first vector in detail
    vector = data['unregistration_confirmation'][0]
    print(f"\n--- Detailed Analysis: {vector['actor']} ---")
    
    # Check ETH message structure
    success = analyze_eth_message(vector['eth_message'])
    
    if not success:
        analyze_actual_structure(vector['eth_message'])
    
    print("-" * 40)

if __name__ == "__main__":
    main() 
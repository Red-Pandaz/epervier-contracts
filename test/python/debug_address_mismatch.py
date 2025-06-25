#!/usr/bin/env python3
import json

def debug_address_mismatch():
    """Debug the address mismatch between signature recovery and base PQ message."""
    
    # Load the registration vectors
    with open('test_vectors/registration_vectors_20250625_131456.json', 'r') as f:
        vectors = json.load(f)
    
    # Get Alice's registration intent vector (first one)
    alice_vector = vectors['registration_intent'][0]
    
    print("=== ALICE'S ADDRESS MISMATCH DEBUG ===")
    print(f"Actor: {alice_vector['actor']}")
    print(f"Expected ETH Address: {alice_vector['eth_address']}")
    print(f"PQ Fingerprint: {alice_vector['pq_fingerprint']}")
    print()
    
    # Get the base PQ message
    base_pq_message_hex = alice_vector['base_pq_message']
    base_pq_message = bytes.fromhex(base_pq_message_hex)
    
    print(f"Base PQ Message length: {len(base_pq_message)} bytes")
    print(f"Base PQ Message hex: {base_pq_message_hex}")
    print()
    
    # Extract address from base PQ message (position 59-79)
    if len(base_pq_message) >= 79:
        address_bytes = base_pq_message[59:79]
        extracted_address = "0x" + address_bytes.hex()
        print(f"Address extracted from base PQ message: {extracted_address}")
    else:
        print("Base PQ message too short")
        return
    
    print()
    print("=== ADDRESS COMPARISON ===")
    print(f"Expected ETH address: {alice_vector['eth_address']}")
    print(f"Extracted from base PQ: {extracted_address}")
    
    if extracted_address.lower() == alice_vector['eth_address'].lower():
        print("✅ Addresses match")
    else:
        print("❌ Addresses don't match")
        print(f"  Expected: {alice_vector['eth_address']}")
        print(f"  Got:      {extracted_address}")
    
    print()
    print("=== SIGNATURE RECOVERY COMPARISON ===")
    print("From contract debug output:")
    print("Recovered ETH address from signature: 0x8906cf5e39c249ec612ecd6420abf0fbd3e13b0b")
    print("Parsed intent address from base PQ:   0x4b5a2d38c249ec612ecd6420abf0fbd3e13b0b")
    print()
    print("The issue is that the signature was created by a different address than what's in the base PQ message!")
    print("This suggests that either:")
    print("1. The wrong private key was used to sign the message")
    print("2. The wrong address was encoded in the base PQ message")
    print("3. There's a bug in the message construction")

if __name__ == "__main__":
    debug_address_mismatch() 
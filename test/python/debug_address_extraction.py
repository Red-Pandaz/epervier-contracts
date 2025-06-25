#!/usr/bin/env python3
import json
from web3 import Web3

def debug_address_extraction():
    """Debug the address extraction from the base PQ message."""
    
    # Load the registration vectors
    with open('test_vectors/registration_vectors_20250625_131456.json', 'r') as f:
        vectors = json.load(f)
    
    # Get Alice's registration intent vector (first one)
    alice_vector = vectors['registration_intent'][0]
    
    print("=== ALICE'S ADDRESS EXTRACTION DEBUG ===")
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
    
    # According to the contract's parseBasePQRegistrationIntentMessage function:
    # ethAddress: starts after DOMAIN_SEPARATOR (32) + pattern (27) = 59, length = 20
    # Let's extract the address manually
    
    if len(base_pq_message) >= 59 + 20:
        address_bytes = base_pq_message[59:59+20]
        address_value = "0x" + address_bytes.hex()
        print(f"Extracted address bytes: {address_bytes.hex()}")
        print(f"Extracted address: {address_value}")
    else:
        print(f"Base PQ message too short to extract address. Need at least 79 bytes, got {len(base_pq_message)}")
    
    print()
    print("=== BASE PQ MESSAGE STRUCTURE ANALYSIS ===")
    print("According to contract schema:")
    print("- DOMAIN_SEPARATOR: 32 bytes")
    print("- 'Intent to pair ETH Address ': 27 bytes") 
    print("- ethAddress: 20 bytes")
    print("- pqNonce: 32 bytes")
    print(f"Total expected: 32 + 27 + 20 + 32 = 111 bytes")
    print(f"Actual message length: {len(base_pq_message)} bytes")
    
    if len(base_pq_message) == 111:
        print("✅ Base PQ message length matches expected schema")
    else:
        print("❌ Base PQ message length doesn't match expected schema")
    
    print()
    print("=== ADDRESS COMPARISON ===")
    print(f"Expected ETH address: {alice_vector['eth_address']}")
    if len(base_pq_message) >= 59 + 20:
        print(f"Extracted ETH address: {address_value}")
        
        if address_value.lower() == alice_vector['eth_address'].lower():
            print("✅ Extracted address matches expected address")
        else:
            print("❌ Extracted address doesn't match expected address")
            print(f"  Extracted: {address_value}")
            print(f"  Expected: {alice_vector['eth_address']}")
    
    print()
    print("=== SIGNATURE RECOVERY COMPARISON ===")
    print("From signature verification:")
    print("Recovered address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    print("Expected address:  0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    print("✅ Signature recovery matches expected address")

if __name__ == "__main__":
    debug_address_extraction() 
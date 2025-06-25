#!/usr/bin/env python3
import json
from web3 import Web3

def debug_nonce():
    """Debug the nonce extraction from the ETH message."""
    
    # Load the registration vectors
    with open('test_vectors/registration_vectors_20250625_131456.json', 'r') as f:
        vectors = json.load(f)
    
    # Get Alice's registration intent vector (first one)
    alice_vector = vectors['registration_intent'][0]
    
    print("=== ALICE'S REGISTRATION VECTOR NONCE DEBUG ===")
    print(f"Actor: {alice_vector['actor']}")
    print(f"ETH Address: {alice_vector['eth_address']}")
    print(f"PQ Fingerprint: {alice_vector['pq_fingerprint']}")
    print()
    
    # Get the message
    eth_message_hex = alice_vector['eth_message']
    eth_message = bytes.fromhex(eth_message_hex)
    
    print(f"ETH Message length: {len(eth_message)} bytes")
    print()
    
    # According to the contract's parseETHRegistrationIntentMessage function:
    # ethNonce: starts after hint = 2258 + 32 = 2290, length = 32
    # Let's extract the nonce manually
    
    if len(eth_message) >= 2290 + 32:
        nonce_bytes = eth_message[2290:2290+32]
        nonce_value = int.from_bytes(nonce_bytes, 'big')
        print(f"Extracted nonce bytes: {nonce_bytes.hex()}")
        print(f"Extracted nonce value: {nonce_value}")
    else:
        print(f"Message too short to extract nonce. Need at least 2322 bytes, got {len(eth_message)}")
    
    print()
    print("=== MESSAGE STRUCTURE ANALYSIS ===")
    print("According to contract schema:")
    print("- DOMAIN_SEPARATOR: 32 bytes")
    print("- 'Intent to pair Epervier Key': 27 bytes") 
    print("- basePQMessage: 111 bytes")
    print("- salt: 40 bytes")
    print("- cs1: 1024 bytes (32 * 32)")
    print("- cs2: 1024 bytes (32 * 32)")
    print("- hint: 32 bytes")
    print("- ethNonce: 32 bytes")
    print(f"Total expected: 32 + 27 + 111 + 40 + 1024 + 1024 + 32 + 32 = 2322 bytes")
    print(f"Actual message length: {len(eth_message)} bytes")
    
    if len(eth_message) == 2322:
        print("✅ Message length matches expected schema")
    else:
        print("❌ Message length doesn't match expected schema")
    
    print()
    print("=== NONCE COMPARISON ===")
    print(f"Test vector eth_nonce: {alice_vector['eth_nonce']}")
    print(f"Test vector pq_nonce: {alice_vector['pq_nonce']}")
    
    # Check if the nonce in the message matches the test vector
    if len(eth_message) >= 2290 + 32:
        if nonce_value == alice_vector['eth_nonce']:
            print("✅ Extracted nonce matches test vector")
        else:
            print("❌ Extracted nonce doesn't match test vector")
            print(f"  Extracted: {nonce_value}")
            print(f"  Expected: {alice_vector['eth_nonce']}")

if __name__ == "__main__":
    debug_nonce() 
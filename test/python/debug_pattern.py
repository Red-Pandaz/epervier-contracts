#!/usr/bin/env python3
import json

def debug_pattern():
    """Debug the pattern matching in the ETH message."""
    
    # Load the registration vectors
    with open('test_vectors/registration_vectors_20250625_131456.json', 'r') as f:
        vectors = json.load(f)
    
    # Get Alice's registration intent vector (first one)
    alice_vector = vectors['registration_intent'][0]
    
    print("=== ALICE'S PATTERN DEBUG ===")
    print(f"Actor: {alice_vector['actor']}")
    print(f"ETH Address: {alice_vector['eth_address']}")
    print()
    
    # Get the message
    eth_message_hex = alice_vector['eth_message']
    eth_message = bytes.fromhex(eth_message_hex)
    
    print(f"ETH Message length: {len(eth_message)} bytes")
    print()
    
    # Check for the expected pattern
    expected_pattern = b"Intent to pair Epervier Key"
    print(f"Expected pattern: {expected_pattern}")
    print(f"Expected pattern length: {len(expected_pattern)} bytes")
    print()
    
    # Search for the pattern
    pattern_found = False
    pattern_index = -1
    
    for i in range(len(eth_message) - len(expected_pattern) + 1):
        if eth_message[i:i+len(expected_pattern)] == expected_pattern:
            pattern_found = True
            pattern_index = i
            break
    
    if pattern_found:
        print(f"✅ Pattern found at index: {pattern_index}")
        
        # Show the context around the pattern
        start = max(0, pattern_index - 10)
        end = min(len(eth_message), pattern_index + len(expected_pattern) + 10)
        
        print(f"Context around pattern (index {start} to {end}):")
        context = eth_message[start:end]
        print(f"  Hex: {context.hex()}")
        print(f"  Text: {context}")
        
        # Verify the pattern is at the expected position
        # According to contract: DOMAIN_SEPARATOR (32) + pattern (27) = 59
        expected_index = 32
        if pattern_index == expected_index:
            print(f"✅ Pattern is at expected position (index {expected_index})")
        else:
            print(f"❌ Pattern is at wrong position. Expected {expected_index}, got {pattern_index}")
            
    else:
        print("❌ Pattern not found in message")
        
        # Show the first part of the message to see what's there
        print("First 100 bytes of message:")
        first_100 = eth_message[:100]
        print(f"  Hex: {first_100.hex()}")
        print(f"  Text: {first_100}")
        
        # Try to find similar patterns
        print("\nSearching for similar patterns...")
        for i in range(len(eth_message) - 20):
            chunk = eth_message[i:i+20]
            if b"Intent" in chunk:
                print(f"  Found 'Intent' at index {i}: {chunk}")
            if b"Epervier" in chunk:
                print(f"  Found 'Epervier' at index {i}: {chunk}")
            if b"Key" in chunk:
                print(f"  Found 'Key' at index {i}: {chunk}")

if __name__ == "__main__":
    debug_pattern() 
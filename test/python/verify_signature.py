#!/usr/bin/env python3
import json
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

def verify_signature():
    """Verify the ETH signature in the registration vector."""
    
    # Load the registration vectors
    with open('test_vectors/registration_vectors_20250625_131456.json', 'r') as f:
        vectors = json.load(f)
    
    # Get Alice's registration intent vector (first one)
    alice_vector = vectors['registration_intent'][0]
    
    print("=== ALICE'S REGISTRATION VECTOR VERIFICATION ===")
    print(f"Actor: {alice_vector['actor']}")
    print(f"ETH Address: {alice_vector['eth_address']}")
    print(f"PQ Fingerprint: {alice_vector['pq_fingerprint']}")
    print()
    
    # Get the message and signature
    eth_message_hex = alice_vector['eth_message']
    eth_message = bytes.fromhex(eth_message_hex)
    
    signature_v = alice_vector['eth_signature']['v']
    signature_r = alice_vector['eth_signature']['r']
    signature_s = alice_vector['eth_signature']['s']
    
    print(f"ETH Message (hex): {eth_message_hex}")
    print(f"Message length: {len(eth_message)} bytes")
    print()
    print(f"Signature v: {signature_v}")
    print(f"Signature r: {signature_r}")
    print(f"Signature s: {signature_s}")
    print()
    
    # Create the signature bytes
    sig_bytes = signature_r.to_bytes(32, 'big') + signature_s.to_bytes(32, 'big') + bytes([signature_v])
    print(f"Signature bytes (hex): {sig_bytes.hex()}")
    print()
    
    # Recover the address from the signature
    try:
        # Create the message hash
        message_hash = Web3.keccak(eth_message)
        print(f"Message hash: {message_hash.hex()}")
        print()
        
        # Recover the address using the correct method
        recovered_address = Account._recover_hash(message_hash, vrs=(signature_v - 27, signature_r, signature_s))
        print(f"Recovered address: {recovered_address}")
        print(f"Expected address:  {alice_vector['eth_address']}")
        print()
        
        # Check if they match
        if recovered_address.lower() == alice_vector['eth_address'].lower():
            print("✅ SIGNATURE IS VALID - Addresses match!")
        else:
            print("❌ SIGNATURE IS INVALID - Addresses don't match!")
            print(f"Difference: {recovered_address} vs {alice_vector['eth_address']}")
            
    except Exception as e:
        print(f"❌ Error recovering address: {e}")
    
    print()
    print("=== MESSAGE ANALYSIS ===")
    print(f"Message starts with: {eth_message[:50].hex()}")
    print(f"Message ends with: {eth_message[-50:].hex()}")
    
    # Try to decode the message as text
    try:
        message_text = eth_message.decode('utf-8', errors='ignore')
        print(f"Message as text: {repr(message_text)}")
    except:
        print("Could not decode message as text")
    
    # Check if message contains the expected components
    if b"Intent to pair Epervier Key" in eth_message:
        print("✅ Message contains 'Intent to pair Epervier Key'")
    else:
        print("❌ Message does not contain 'Intent to pair Epervier Key'")
    
    if alice_vector['eth_address'].lower()[2:].encode() in eth_message:
        print("✅ Message contains ETH address")
    else:
        print("❌ Message does not contain ETH address")
    
    # Check what the message should be
    print()
    print("=== EXPECTED MESSAGE FORMAT ===")
    expected_message = f"Intent to pair Epervier Key_ETH Address {alice_vector['eth_address']}"
    print(f"Expected message: {expected_message}")
    print(f"Expected message hex: {expected_message.encode().hex()}")
    
    # Try to recover with the expected message
    try:
        expected_hash = Web3.keccak(expected_message.encode())
        print(f"Expected message hash: {expected_hash.hex()}")
        
        recovered_from_expected = Account._recover_hash(expected_hash, vrs=(signature_v - 27, signature_r, signature_s))
        print(f"Recovered from expected message: {recovered_from_expected}")
        
        if recovered_from_expected.lower() == alice_vector['eth_address'].lower():
            print("✅ SIGNATURE WORKS WITH EXPECTED MESSAGE FORMAT!")
        else:
            print("❌ SIGNATURE DOESN'T WORK WITH EXPECTED MESSAGE FORMAT")
            
    except Exception as e:
        print(f"❌ Error with expected message: {e}")

if __name__ == "__main__":
    verify_signature() 
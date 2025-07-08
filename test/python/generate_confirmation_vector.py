#!/usr/bin/env python3

import json
import struct
from pathlib import Path

def create_base_pq_unregistration_confirm_message(eth_address, pq_nonce):
    """Create BasePQUnregistrationConfirmMessage (124 bytes)"""
    # DOMAIN_SEPARATOR (32 bytes) - placeholder
    domain_separator = b'\x00' * 32
    
    # pattern: "Confirm unregistration from ETH Address " (40 bytes)
    pattern = b"Confirm unregistration from ETH Address "
    
    # ethAddress (20 bytes)
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    
    # pqNonce (32 bytes)
    pq_nonce_bytes = pq_nonce.to_bytes(32, 'big')
    
    # Total: 32 + 40 + 20 + 32 = 124 bytes
    base_pq_message = domain_separator + pattern + eth_address_bytes + pq_nonce_bytes
    
    return base_pq_message

def create_eth_unregistration_confirmation_message(pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    """Create ETHUnregistrationConfirmationMessage (2375 bytes)"""
    # pattern: "Confirm unregistration from Epervier Fingerprint " (49 bytes)
    pattern = b"Confirm unregistration from Epervier Fingerprint "
    
    # pqFingerprint (20 bytes)
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    
    # basePQMessage (124 bytes) - already created
    base_pq_message_bytes = base_pq_message
    
    # salt (40 bytes)
    salt_bytes = bytes.fromhex(salt)
    
    # cs1 (1024 bytes) - 32 uint256 values
    cs1_bytes = b''
    for value in cs1:
        cs1_bytes += value.to_bytes(32, 'big')
    
    # cs2 (1024 bytes) - 32 uint256 values
    cs2_bytes = b''
    for value in cs2:
        cs2_bytes += value.to_bytes(32, 'big')
    
    # hint (32 bytes)
    hint_bytes = hint.to_bytes(32, 'big')
    
    # ethNonce (32 bytes)
    eth_nonce_bytes = eth_nonce.to_bytes(32, 'big')
    
    # Total: 49 + 20 + 124 + 40 + 1024 + 1024 + 32 + 32 = 2345 bytes
    eth_message = pattern + pq_fingerprint_bytes + base_pq_message_bytes + salt_bytes + cs1_bytes + cs2_bytes + hint_bytes + eth_nonce_bytes
    
    return eth_message

def generate_confirmation_vector():
    """Generate a properly formatted unregistration confirmation vector"""
    
    # Example values (you would get these from your actual data)
    eth_address = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"  # Alice's address
    pq_fingerprint = "0x7b317f4d231cbc63de7c6c690ef4ba9c653437fb"  # Alice's PQ fingerprint
    pq_nonce = 2
    eth_nonce = 3
    
    # Create base PQ message
    base_pq_message = create_base_pq_unregistration_confirm_message(eth_address, pq_nonce)
    
    # Example signature components (you would get these from actual signing)
    salt = "9d7733f7cbb35fa9486fd840ff4a72139d1192e35fd9fe12d4891a0d12255c0cea4af8e8bae6142b"
    
    # Example cs1 and cs2 (32 uint256 values each)
    cs1 = [0] * 32  # Placeholder - you'd get actual values
    cs2 = [0] * 32  # Placeholder - you'd get actual values
    
    hint = 12345  # Placeholder - you'd get actual value
    
    # Create ETH message
    eth_message = create_eth_unregistration_confirmation_message(
        pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce
    )
    
    # Example ETH signature (you would get this from actual signing)
    eth_signature = {
        "v": 28,
        "r": "0x1234567890123456789012345678901234567890123456789012345678901234",
        "s": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
    }
    
    # Create the vector
    vector = {
        "description": "Valid unregistration confirmation for Alice",
        "eth_message": eth_message.hex(),
        "eth_signature": eth_signature
    }
    
    return vector

def main():
    """Generate and save the confirmation vector"""
    print("Generating unregistration confirmation vector...")
    
    vector = generate_confirmation_vector()
    
    # Save to file
    output_path = Path("test/test_vectors/generated_confirmation_vector.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump({
            "unregistration_confirmation": [vector]
        }, f, indent=2)
    
    print(f"Generated confirmation vector saved to {output_path}")
    print(f"ETH message length: {len(bytes.fromhex(vector['eth_message']))} bytes")
    print(f"Expected length: 2345 bytes")

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from eip712_config import *
import hashlib

def keccak256(data):
    """Compute keccak256 hash"""
    return hashlib.sha3_256(data).digest()

def main():
    # Test data
    pq_fingerprint = "0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb"
    eth_nonce = 1
    
    print("Testing struct hash calculation:")
    print(f"  pqFingerprint: {pq_fingerprint}")
    print(f"  ethNonce: {eth_nonce}")
    print(f"  REGISTRATION_CONFIRMATION_TYPE_HASH: {REGISTRATION_CONFIRMATION_TYPE_HASH}")
    
    # Convert to bytes
    type_hash_bytes = bytes.fromhex(REGISTRATION_CONFIRMATION_TYPE_HASH[2:])
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])
    eth_nonce_bytes = eth_nonce.to_bytes(32, 'big')
    
    print(f"\nBytes:")
    print(f"  type_hash: {type_hash_bytes.hex()}")
    print(f"  pq_fingerprint: {pq_fingerprint_bytes.hex()}")
    print(f"  eth_nonce: {eth_nonce_bytes.hex()}")
    
    # Manual encoding (like Solidity's abi.encode)
    # Solidity's abi.encode() for (bytes32, address, uint256) should be:
    # - bytes32: 32 bytes, left-aligned
    # - address: 32 bytes, right-aligned (20 bytes of address + 12 bytes of padding)
    # - uint256: 32 bytes, right-aligned
    
    # Manual encoding
    manual_encoded = (
        type_hash_bytes +  # 32 bytes, left-aligned
        b'\x00' * 12 + pq_fingerprint_bytes +  # address: 12 bytes padding + 20 bytes address
        eth_nonce_bytes  # uint256: 32 bytes
    )
    
    print(f"\nManual encoding (Solidity-style):")
    print(f"  encoded: {manual_encoded.hex()}")
    print(f"  length: {len(manual_encoded)} bytes")
    
    # Calculate struct hash
    manual_struct_hash = keccak256(manual_encoded)
    print(f"  struct_hash: {manual_struct_hash.hex()}")
    
    # Compare with Python's eth_abi encoding
    try:
        from eth_abi import encode
        
        # eth_abi encoding
        eth_abi_encoded = encode(['bytes32', 'address', 'uint256'], [
            type_hash_bytes,  # Pass as bytes, not hex string
            pq_fingerprint,
            eth_nonce
        ])
        
        print(f"\neth_abi encoding:")
        print(f"  encoded: {eth_abi_encoded.hex()}")
        print(f"  length: {len(eth_abi_encoded)} bytes")
        
        # Calculate struct hash
        eth_abi_struct_hash = keccak256(eth_abi_encoded)
        print(f"  struct_hash: {eth_abi_struct_hash.hex()}")
        
        # Compare
        print(f"\nComparison:")
        print(f"  encodings match: {manual_encoded == eth_abi_encoded}")
        print(f"  struct_hashes match: {manual_struct_hash == eth_abi_struct_hash}")
        
        if manual_struct_hash != eth_abi_struct_hash:
            print(f"\nDIFFERENCE FOUND!")
            print(f"  Manual struct_hash:     {manual_struct_hash.hex()}")
            print(f"  eth_abi struct_hash:    {eth_abi_struct_hash.hex()}")
            
            # Show the difference in the encoded data
            print(f"\nEncoded data comparison:")
            for i, (m, e) in enumerate(zip(manual_encoded, eth_abi_encoded)):
                if m != e:
                    print(f"  Byte {i}: manual={m:02x}, eth_abi={e:02x}")
        
    except ImportError:
        print("eth_abi not available, skipping comparison")

if __name__ == "__main__":
    main() 
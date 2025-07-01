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
    # Test data from the failing test
    pq_fingerprint = "0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb"
    eth_nonce = 1
    
    print("Testing struct hash calculation with exact test data:")
    print(f"  pqFingerprint: {pq_fingerprint}")
    print(f"  ethNonce: {eth_nonce}")
    print(f"  REGISTRATION_CONFIRMATION_TYPE_HASH: {REGISTRATION_CONFIRMATION_TYPE_HASH}")
    
    # Convert to bytes
    type_hash_bytes = bytes.fromhex(REGISTRATION_CONFIRMATION_TYPE_HASH[2:])
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])
    eth_nonce_bytes = eth_nonce.to_bytes(32, 'big')
    
    print(f"\nBytes:")
    print(f"  type_hash_bytes: {type_hash_bytes.hex()}")
    print(f"  pq_fingerprint_bytes: {pq_fingerprint_bytes.hex()}")
    print(f"  eth_nonce_bytes: {eth_nonce_bytes.hex()}")
    
    # Manual encoding (like Solidity's abi.encode)
    # Solidity abi.encode() pads addresses to 32 bytes
    padded_pq_fingerprint = b'\x00' * 12 + pq_fingerprint_bytes  # Pad to 32 bytes
    manual_encoded = type_hash_bytes + padded_pq_fingerprint + eth_nonce_bytes
    print(f"\nManual encoding (like Solidity abi.encode):")
    print(f"  encoded: {manual_encoded.hex()}")
    print(f"  length: {len(manual_encoded)} bytes")
    
    # eth_abi encoding
    try:
        from eth_abi import encode
        eth_abi_encoded = encode(['bytes32', 'address', 'uint256'], [
            type_hash_bytes,
            pq_fingerprint,
            eth_nonce
        ])
        print(f"\neth_abi encoding:")
        print(f"  encoded: {eth_abi_encoded.hex()}")
        print(f"  length: {len(eth_abi_encoded)} bytes")
        print(f"  Match: {manual_encoded == eth_abi_encoded}")
    except ImportError:
        print("eth_abi not available")
    
    # Calculate struct hashes
    manual_struct_hash = keccak256(manual_encoded)
    print(f"\nStruct hashes:")
    print(f"  Manual (like Solidity): {manual_struct_hash.hex()}")
    
    if 'eth_abi_encoded' in locals():
        eth_abi_struct_hash = keccak256(eth_abi_encoded)
        print(f"  eth_abi: {eth_abi_struct_hash.hex()}")
        print(f"  Match: {manual_struct_hash == eth_abi_struct_hash}")
    
    # Calculate EIP712 digests
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    manual_digest = keccak256(b'\x19\x01' + domain_separator_bytes + manual_struct_hash)
    print(f"\nEIP712 digests:")
    print(f"  Manual (like Solidity): {manual_digest.hex()}")
    
    if 'eth_abi_struct_hash' in locals():
        eth_abi_digest = keccak256(b'\x19\x01' + domain_separator_bytes + eth_abi_struct_hash)
        print(f"  eth_abi: {eth_abi_digest.hex()}")
        print(f"  Match: {manual_digest == eth_abi_digest}")
    
    # Contract digest from test trace
    contract_digest = "7cfbec6803b26959cf284231ac0a6ec2718e0617814b3ab8d6b74652d09fb2cf"
    print(f"\nContract digest from test trace: {contract_digest}")
    print(f"  Manual matches contract: {manual_digest.hex() == contract_digest}")
    if 'eth_abi_digest' in locals():
        print(f"  eth_abi matches contract: {eth_abi_digest.hex() == contract_digest}")

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from eip712_config import *

def create_base_eth_message(pq_fingerprint, eth_nonce):
    """
    Create base ETH message for registration confirmation
    Format: "Confirm bonding to Epervier Fingerprint " + pqFingerprint + ethNonce
    This is signed by the ETH Address (no domain separator in content)
    """
    base_eth_pattern = "Confirm bonding to Epervier Fingerprint "
    message = (
        base_eth_pattern.encode() +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def main():
    # Test with Alice's data
    pq_fingerprint = "0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb"
    eth_nonce = 1
    
    # Create the base message
    base_message = create_base_eth_message(pq_fingerprint, eth_nonce)
    
    print("Python base message creation:")
    print(f"  Pattern: 'Confirm bonding to Epervier Fingerprint '")
    print(f"  Pattern length: {len('Confirm bonding to Epervier Fingerprint ')} bytes")
    print(f"  pqFingerprint: {pq_fingerprint}")
    print(f"  pqFingerprint bytes: {bytes.fromhex(pq_fingerprint[2:]).hex()}")
    print(f"  ethNonce: {eth_nonce}")
    print(f"  ethNonce bytes: {eth_nonce.to_bytes(32, 'big').hex()}")
    print(f"  Total message: {base_message.hex()}")
    print(f"  Total length: {len(base_message)} bytes")
    
    # Decode the message to see what it looks like
    print(f"\nDecoded message: {base_message.decode('ascii', errors='replace')}")
    
    # Contract parsing analysis
    print(f"\nContract parsing analysis:")
    pattern = "Confirm bonding to Epervier Fingerprint "
    pattern_length = len(pattern)
    print(f"  Contract expects pattern: '{pattern}'")
    print(f"  Pattern length: {pattern_length} bytes")
    print(f"  pqFingerprint should start at offset: {pattern_length}")
    print(f"  pqFingerprint should end at offset: {pattern_length + 20}")
    print(f"  ethNonce should start at offset: {pattern_length + 20}")
    print(f"  ethNonce should end at offset: {pattern_length + 20 + 32}")
    
    # Extract what the contract would extract
    extracted_pq_fingerprint = base_message[pattern_length:pattern_length + 20]
    extracted_eth_nonce = base_message[pattern_length + 20:pattern_length + 20 + 32]
    
    print(f"\nContract would extract:")
    print(f"  pqFingerprint bytes: {extracted_pq_fingerprint.hex()}")
    print(f"  pqFingerprint as address: 0x{extracted_pq_fingerprint.hex()}")
    print(f"  ethNonce bytes: {extracted_eth_nonce.hex()}")
    print(f"  ethNonce as uint256: {int.from_bytes(extracted_eth_nonce, 'big')}")
    
    # Compare with expected values
    expected_pq_fingerprint = bytes.fromhex(pq_fingerprint[2:])
    expected_eth_nonce = eth_nonce.to_bytes(32, 'big')
    
    print(f"\nComparison:")
    print(f"  pqFingerprint match: {extracted_pq_fingerprint == expected_pq_fingerprint}")
    print(f"  ethNonce match: {extracted_eth_nonce == expected_eth_nonce}")

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
Debug script to compare struct hash calculations
"""

import sys
import os
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from eip712_helpers import get_change_eth_address_intent_struct_hash, get_eip712_digest, encode_packed
from eip712_config import DOMAIN_SEPARATOR, CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH
from vector_generators.change_eth.change_eth_address_intent_generator import create_base_eth_message

def main():
    # Load the actual test vector
    test_vector_file = "../../test/test_vectors/change_eth/change_eth_address_intent_vectors.json"
    with open(test_vector_file, 'r') as f:
        data = json.load(f)
    
    # Get the first test vector (alice -> bob)
    test_vector = data["change_eth_address_intent"][0]
    
    # Extract the actual values from the test vector
    new_eth_address = test_vector["new_eth_address"]  # Should be Bob's address
    eth_nonce = test_vector["eth_nonce"]
    pq_fingerprint = test_vector["pq_fingerprint"]
    
    print(f"Testing struct hash calculation with actual test vector:")
    print(f"current_actor: {test_vector['current_actor']}")
    print(f"new_actor: {test_vector['new_actor']}")
    print(f"new_eth_address: {new_eth_address}")
    print(f"eth_nonce: {eth_nonce}")
    print(f"pq_fingerprint: {pq_fingerprint}")
    print(f"type_hash: {CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH}")
    print(f"domain_separator: {DOMAIN_SEPARATOR}")
    
    # Calculate struct hash
    struct_hash = get_change_eth_address_intent_struct_hash(new_eth_address, eth_nonce)
    print(f"Python struct hash: {struct_hash.hex()}")
    
    # Calculate EIP-712 digest
    domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    digest = get_eip712_digest(domain_separator, struct_hash)
    print(f"Python EIP-712 digest: {digest.hex()}")
    
    # Show the exact bytes being hashed for the digest
    digest_input = encode_packed(b'\x19\x01', domain_separator, struct_hash)
    print(f"Python digest input bytes: {digest_input.hex()}")
    print(f"Python digest input length: {len(digest_input)} bytes")
    
    # Create the base ETH message to verify it matches
    base_eth_message = create_base_eth_message(pq_fingerprint, new_eth_address, eth_nonce)
    print(f"Base ETH message (hex): {base_eth_message.hex()}")
    print(f"Base ETH message length: {len(base_eth_message)} bytes")
    
    # Show the expected values from the contract debug output
    print(f"\nContract debug output showed:")
    print(f"Contract struct hash: 52966052908639116320611577402999322366478840493372048364309297150041786066955")
    print(f"Contract digest: 51460757169433229389292576700603448031583843588807979553548374176927218909789")
    print(f"Contract extracted newEthAddress: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
    
    # Convert contract values to hex for comparison
    contract_struct_hash_hex = hex(52966052908639116320611577402999322366478840493372048364309297150041786066955)
    contract_digest_hex = hex(51460757169433229389292576700603448031583843588807979553548374176927218909789)
    
    print(f"\nComparison:")
    print(f"Struct hash match: {struct_hash.hex() == contract_struct_hash_hex[2:]}")
    print(f"Digest match: {digest.hex() == contract_digest_hex[2:]}")
    
    # Show what the contract should be hashing
    print(f"\nContract should be hashing:")
    print(f"\\x19\\x01 + domain_separator + struct_hash")
    prefix = b'\x19\x01'
    print(f"\\x19\\x01: {prefix.hex()}")
    print(f"domain_separator: {domain_separator.hex()}")
    print(f"struct_hash: {struct_hash.hex()}")
    print(f"Expected contract digest input: {prefix.hex() + domain_separator.hex() + struct_hash.hex()}")

if __name__ == "__main__":
    main() 
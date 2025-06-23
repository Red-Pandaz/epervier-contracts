#!/usr/bin/env python3

import os
import sys
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak
import hashlib

# Add the project root to the path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

def main():
    # Use the same private key as before
    private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    account = Account.from_key(private_key)
    print(f"Account address: {account.address}")
    
    # Domain separator from contract
    DOMAIN_SEPARATOR = keccak(b"PQRegistry")
    print(f"DOMAIN_SEPARATOR: {DOMAIN_SEPARATOR.hex()}")
    
    # Test with nonce 1
    ethNonce = 1
    
    # Create the message exactly as the contract does
    # In Solidity: abi.encodePacked(DOMAIN_SEPARATOR, "Intent to pair Epervier Key", ethNonce)
    # This is equivalent to concatenating the bytes
    ethIntentMessage = DOMAIN_SEPARATOR + b"Intent to pair Epervier Key" + ethNonce.to_bytes(32, 'big')
    print(f"ethIntentMessage: {ethIntentMessage.hex()}")
    
    # Hash the message
    ethMessageHash = keccak(ethIntentMessage)
    print(f"ethMessageHash: {ethMessageHash.hex()}")
    
    # Create the signed message hash
    ethSignedMessageHash = keccak(
        b"\x19Ethereum Signed Message:\n32" + ethMessageHash
    )
    print(f"ethSignedMessageHash: {ethSignedMessageHash.hex()}")
    
    # Sign the message
    message = encode_defunct(ethMessageHash)
    signed_message = account.sign_message(message)
    print(f"Signature: {signed_message.signature.hex()}")
    print(f"r: 0x{signed_message.r:064x}")
    print(f"s: 0x{signed_message.s:064x}")
    print(f"v: {signed_message.v}")
    
    # Verify the signature
    recovered_address = Account.recover_message(message, signature=signed_message.signature)
    print(f"Recovered address: {recovered_address}")
    print(f"Expected address: {account.address}")
    print(f"Match: {recovered_address.lower() == account.address.lower()}")

if __name__ == "__main__":
    main() 
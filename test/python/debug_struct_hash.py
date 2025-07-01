#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from eip712_config import *
from eip712_helpers import encode_registration_confirmation_data, get_registration_confirmation_struct_hash, get_eip712_digest
import hashlib

def keccak256(data):
    return hashlib.sha3_256(data).digest()

def main():
    # Alice's data
    pq_fingerprint = "0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb"
    eth_nonce = 1
    eth_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    eth_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

    # Struct hash
    struct_hash = get_registration_confirmation_struct_hash(pq_fingerprint, eth_nonce)
    print(f"Struct hash: {struct_hash.hex()}")

    # EIP-712 digest
    domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    digest = get_eip712_digest(domain_separator, struct_hash)
    print(f"EIP-712 digest: {digest.hex()}")

    # Sign the digest using eth_account
    from eth_account import Account
    from eth_account._utils.signing import to_standard_v
    sig = Account._sign_hash(eth_private_key, digest)
    v, r, s = sig.v, sig.r, sig.s
    print(f"Signature components:")
    print(f"  v: {v}")
    print(f"  r: {hex(r)}")
    print(f"  s: {hex(s)}")
    print(f"  address from private key: {Account.from_key(eth_private_key).address}")

    # Recover address from signature
    recovered_addr = Account._recover_hash(digest, vrs=(v, r, s))
    print(f"Recovered address: {recovered_addr}")
    print(f"Expected address:  {eth_address}")
    print(f"Match: {recovered_addr.lower() == eth_address.lower()}")

    # Try with v adjusted to 27/28 if needed
    if v in (0, 1):
        v_adj = v + 27
        recovered_addr_adj = Account._recover_hash(digest, vrs=(v_adj, r, s))
        print(f"Recovered address with v+27: {recovered_addr_adj}")
        print(f"Match (v+27): {recovered_addr_adj.lower() == eth_address.lower()}")

if __name__ == "__main__":
    main() 
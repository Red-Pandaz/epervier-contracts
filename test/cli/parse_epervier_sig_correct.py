#!/usr/bin/env python3
import sys
import os

# Add the python-ref directory to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ETHFALCON/python-ref')))

from falcon_epervier import HEAD_LEN, SALT_LEN, decompress
from common import falcon_compact, q
from polyntt.poly import Poly

def parse_signature_like_cli(sig_path):
    """Parse signature exactly like the CLI does"""
    
    # Read signature file
    with open(sig_path, 'r') as f:
        sig_hex = f.read().strip()
    sig = bytes.fromhex(sig_hex)
    
    print(f"Signature length: {len(sig)} bytes")
    
    # Extract components exactly like CLI
    salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
    print(f"Salt length: {len(salt)} bytes")
    
    # CLI uses: enc_s = sig[HEAD_LEN + SALT_LEN:-512*3]
    enc_s = sig[HEAD_LEN + SALT_LEN:-512*3]
    print(f"Encoded signature length: {len(enc_s)} bytes")
    
    # CLI uses: s = decompress(enc_s, 666*2 - HEAD_LEN - SALT_LEN, 512*2)
    decompress_len = 666*2 - HEAD_LEN - SALT_LEN
    print(f"Decompress length: {decompress_len}")
    
    s = decompress(enc_s, decompress_len, 512*2)
    mid = len(s) // 2
    s = [elt % q for elt in s]
    s1, s2 = s[:mid], s[mid:]
    
    # Convert to compact format
    s1_compact = falcon_compact(s1)
    s2_compact = falcon_compact(s2)
    
    # Calculate hint like CLI
    s2_inv_ntt = Poly(s2, q).inverse().ntt()
    hint = 1
    for elt in s2_inv_ntt:
        hint = (hint * elt) % q
    
    print(f"Salt: {salt.hex()}")
    print(f"cs1: {s1_compact}")
    print(f"cs2: {s2_compact}")
    print(f"hint: {hint}")
    
    return {
        'salt': salt.hex(),
        'cs1': s1_compact,
        'cs2': s2_compact,
        'hint': hint
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_epervier_sig_correct.py <sig_file>")
        sys.exit(1)
    
    sig_path = sys.argv[1]
    result = parse_signature_like_cli(sig_path)
    
    print("\n--- Contract Input ---")
    print(f"salt = bytes.fromhex('{result['salt']}')")
    print(f"cs1 = {result['cs1']}")
    print(f"cs2 = {result['cs2']}")
    print(f"hint = {result['hint']}") 
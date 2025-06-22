#!/usr/bin/env python3
"""
Script to parse Epervier signatures and extract components for Solidity tests.
"""

import sys
import os

from falcon_epervier import EpervierPublicKey, EpervierSecretKey, HEAD_LEN, SALT_LEN, decompress
from common import falcon_compact, q
from polyntt.poly import Poly

def parse_signature(sig_file, pk_file):
    """Parse a signature file and extract components."""
    
    # Load signature
    with open(sig_file, 'r') as f:
        sig_hex = f.read().strip()
    sig = bytes.fromhex(sig_hex)
    
    # Load public key
    with open(pk_file, 'r') as f:
        data = f.read()
    variables = dict(line.split("=") for line in data.splitlines()[1:])
    n = int(variables["n "])
    pk_value = eval(variables["pk "])
    version = variables["version "].lstrip()
    
    if version != 'epervier':
        raise ValueError(f"Expected epervier version, got {version}")
    
    pk = EpervierPublicKey(n, pk_value)
    
    # Extract components
    salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
    enc_s = sig[HEAD_LEN + SALT_LEN:-pk.n*3]  # Remove last 1536 bytes (512*3)
    
    # Decompress s1 and s2
    s = decompress(enc_s, pk.sig_bytelen * 2 - HEAD_LEN - SALT_LEN, pk.n * 2)
    mid = len(s) // 2
    s = [elt % q for elt in s]
    s1, s2 = s[:mid], s[mid:]
    
    # Convert to compact format
    s1_compact = falcon_compact(s1)
    s2_compact = falcon_compact(s2)
    
    # Calculate hint
    s2_inv_ntt = Poly(s2, q).inverse().ntt()
    hint = 1
    for elt in s2_inv_ntt:
        hint = (hint * elt) % q
    
    return {
        'salt': salt.hex(),
        's1': s1_compact,
        's2': s2_compact, 
        'hint': hint,
        'public_key': pk_value,
        'n': n
    }

def main():
    """Parse all signatures and print results."""
    
    base_dir = "../../test/test_keys"
    
    print("// Auto-generated signature data for Solidity tests")
    print("// Generated from parse_signatures.py")
    print()
    
    for i in range(1, 5):  # sig_1 to sig_4
        sig_file = f"{base_dir}/sig_{i}"
        pk_file = f"{base_dir}/public_key_{i}"
        
        if not os.path.exists(sig_file) or not os.path.exists(pk_file):
            print(f"// Skipping sig_{i} - files not found")
            continue
            
        try:
            result = parse_signature(sig_file, pk_file)
            
            print(f"// Signature {i}")
            print(f"bytes memory salt_{i} = hex\"{result['salt']}\";")
            print(f"uint256[] memory cs1_{i} = {result['s1']};")
            print(f"uint256[] memory cs2_{i} = {result['s2']};")
            print(f"uint256 hint_{i} = {result['hint']};")
            print(f"uint256[2] memory publicKey_{i} = [{result['public_key']}, 0];")
            print()
            
        except Exception as e:
            print(f"// Error parsing sig_{i}: {e}")
            print()

if __name__ == "__main__":
    main() 
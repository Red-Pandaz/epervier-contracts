#!/usr/bin/env python3
"""
Generate unregistration confirmation vector for PQRegistryHappyPath.t.sol
This script creates a valid EIP712 signature for unregistration confirmation.
"""

import json
import hashlib
import subprocess
import sys
from pathlib import Path
from eth_account import Account
from eth_utils import keccak
import os

# Add the python directory to the path to import helpers
sys.path.append(str(Path(__file__).resolve().parent))
from eip712_helpers import get_unregistration_confirmation_struct_hash, sign_eip712_message, encode_packed
from eip712_config import DOMAIN_SEPARATOR

# Alice's private key (from test vectors)
ALICE_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ALICE_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ALICE_PQ_FINGERPRINT = "0x7B317F4D231CBc63dE7C6C690ef4Ba9C653437Fb"
ALICE_PQ_PRIVATE_KEY_FILE = "private_key_1.pem"

# Domain separator from the contract
DOMAIN_SEPARATOR_BYTES = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix

def int_to_bytes32(x):
    """Convert int to bytes32"""
    return x.to_bytes(32, 'big')

def build_base_pq_unregistration_confirm_message(domain_separator, eth_address, pq_nonce):
    """Build base PQ unregistration confirmation message"""
    # DOMAIN_SEPARATOR + "Confirm unregistration from ETH Address " + ethAddress + pqNonce
    pattern = b"Confirm unregistration from ETH Address "
    return domain_separator + pattern + bytes.fromhex(eth_address[2:]) + int_to_bytes32(pq_nonce)

def sign_with_pq_key(base_pq_message, pq_private_key_file):
    """Use sign_cli.py to sign the base PQ message"""
    from tempfile import NamedTemporaryFile
    
    # Write message to temp file
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(base_pq_message)
        tmp.flush()
        tmp_path = tmp.name

    # Get paths
    project_root = Path(__file__).resolve().parents[2]  # Go up to project root
    sign_cli = project_root / "ETHFALCON/python-ref/sign_cli.py"
    privkey_path = project_root / "test/test_keys" / pq_private_key_file
    venv_python = project_root / "ETHFALCON/python-ref/myenv/bin/python3"

    cmd = [
        str(venv_python), str(sign_cli), "sign",
        f"--privkey={privkey_path}",
        f"--data={base_pq_message.hex()}",
        "--version=epervier"
    ]
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    os.unlink(tmp_path)
    print("PQ sign_cli output:")
    print(result.stdout)
    
    # Parse output for salt, hint, cs1, cs2
    lines = result.stdout.splitlines()
    out = {}
    for line in lines:
        if line.startswith("salt:"):
            out["salt"] = bytes.fromhex(line.split()[1])
        elif line.startswith("hint:"):
            out["hint"] = int(line.split()[1])
        elif line.startswith("cs1:"):
            out["cs1"] = [int(x, 16) for x in line.split()[1:]]
        elif line.startswith("cs2:"):
            out["cs2"] = [int(x, 16) for x in line.split()[1:]]
    
    if not all(k in out for k in ["salt", "hint", "cs1", "cs2"]):
        print("Failed to parse PQ signature components!")
        return None
    return out

def create_eth_confirm_message(domain_separator, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    """Create ETH message for unregistration confirmation"""
    pattern = b"Confirm unregistration from Epervier Fingerprint "
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    
    message = (
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        base_pq_message +
        salt +
        pack_uint256_array(cs1) +
        pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') +
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def sign_with_eth_key(eth_message, eth_private_key, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    """Sign a message with ETH private key using EIP712"""
    # Use EIP712 structured signing
    struct_hash = get_unregistration_confirmation_struct_hash(pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce)
    
    # Create EIP712 digest with domain separator
    digest = keccak(encode_packed(b'\x19\x01', DOMAIN_SEPARATOR_BYTES, struct_hash))
    
    print(f"DEBUG: Python domain_separator_bytes: {DOMAIN_SEPARATOR_BYTES.hex()}")
    print(f"DEBUG: Python struct_hash: {struct_hash.hex()}")
    print(f"DEBUG: Python digest: {digest.hex()}")
    
    # Sign the digest
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    
    # Verify the signature immediately
    recovered_address = Account._recover_hash(digest, vrs=(sig.v, sig.r, sig.s))
    print(f"DEBUG: Python recovered_address: {recovered_address}")
    print(f"DEBUG: Python expected_address: {account.address}")
    print(f"DEBUG: Python addresses_match: {recovered_address.lower() == account.address.lower()}")
    
    return {"v": sig.v, "r": sig.r, "s": sig.s}

def generate_vector():
    """Generate the complete unregistration confirmation vector"""
    
    eth_nonce = 3
    pq_nonce = 3
    
    print("Building base PQ unregistration confirmation message...")
    base_pq_message = build_base_pq_unregistration_confirm_message(DOMAIN_SEPARATOR_BYTES, ALICE_ADDRESS, pq_nonce)
    print(f"Base PQ message length: {len(base_pq_message)} bytes")
    print(f"Base PQ message: {base_pq_message.hex()}")
    
    print("Signing with PQ key...")
    pq_sig = sign_with_pq_key(base_pq_message, ALICE_PQ_PRIVATE_KEY_FILE)
    if pq_sig is None:
        print("Failed to generate PQ signature!")
        return None
    
    print(f"PQ signature generated: {len(pq_sig)} components")
    print(f"DEBUG: Python PQ signature components:")
    print(f"  salt: {pq_sig['salt'].hex()}")
    print(f"  hint: {pq_sig['hint']}")
    print(f"  cs1[0]: {pq_sig['cs1'][0]}")
    print(f"  cs1[1]: {pq_sig['cs1'][1]}")
    print(f"  cs2[0]: {pq_sig['cs2'][0]}")
    print(f"  cs2[1]: {pq_sig['cs2'][1]}")
    
    print("Building ETH unregistration confirmation message...")
    eth_confirmation_message = create_eth_confirm_message(
        DOMAIN_SEPARATOR_BYTES, ALICE_PQ_FINGERPRINT, base_pq_message, 
        pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce
    )
    print(f"ETH confirmation message length: {len(eth_confirmation_message)} bytes")
    print(f"ETH confirmation message (hex): {eth_confirmation_message.hex()}")
    
    print("Signing with ETH key...")
    eth_sig = sign_with_eth_key(eth_confirmation_message, ALICE_PRIVATE_KEY, ALICE_PQ_FINGERPRINT, base_pq_message, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce)
    print(f"ETH signature generated: v={eth_sig['v']}, r={eth_sig['r']}, s={eth_sig['s']}")
    
    # Create the vector
    vector = {
        "actor": "alice",
        "eth_address": ALICE_ADDRESS,
        "pq_fingerprint": ALICE_PQ_FINGERPRINT,
        "base_pq_message": base_pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"].hex(),
            "cs1": [hex(x) for x in pq_sig["cs1"]],
            "cs2": [hex(x) for x in pq_sig["cs2"]],
            "hint": pq_sig["hint"]
        },
        "eth_message": eth_confirmation_message.hex(),
        "eth_signature": eth_sig,
        "eth_nonce": eth_nonce,
        "pq_nonce": pq_nonce
    }
    
    return vector

def main():
    """Main function to generate and save the vector"""
    print("Starting unregistration confirmation vector generation...")
    
    vector = generate_vector()
    if vector is None:
        print("Failed to generate vector!")
        return
    
    # Save to the expected file
    output_path = "test/test_vectors/generated_confirmation_vector.json"
    with open(output_path, "w") as f:
        json.dump({"unregistration_confirmation": [vector]}, f, indent=2)
    
    print(f"Generated unregistration confirmation vector:")
    print(json.dumps({"unregistration_confirmation": [vector]}, indent=2))

if __name__ == "__main__":
    main() 
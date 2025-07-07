#!/usr/bin/env python3

import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))  # Add python directory to path
from eip712_helpers import get_unregistration_intent_struct_hash, sign_eip712_message
import hashlib

def encode_packed(*args):
    """Encode packed data (equivalent to abi.encodePacked)"""
    result = b''
    for arg in args:
        if isinstance(arg, bytes):
            result += arg
        elif isinstance(arg, str):
            result += arg.encode('utf-8')
        elif isinstance(arg, int):
            result += arg.to_bytes(32, 'big')
    return result

print("Script loaded successfully!")

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[4]  # epervier-registry
ACTORS_CONFIG_PATH = PROJECT_ROOT / "test" / "test_keys" / "actors_config.json"
OUTPUT_PATH = PROJECT_ROOT / "test/test_vectors/revert/unregistration_revert_vectors.json"
from eip712_config import DOMAIN_SEPARATOR

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')


def load_actors_config():
    # Load the actors config JSON
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]


def create_base_eth_message(domain_separator, pq_fingerprint, eth_nonce):
    """
    Create base ETH message for unregistration intent
    Format: "Intent to unregister from Epervier Fingerprint " + pqFingerprint + ethNonce
    This is signed by the ETH Address (no domain separator in content for EIP712)
    """
    pattern = b"Intent to unregister from Epervier Fingerprint "  # 47 bytes
    message = (
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, 'big')
    )
    return message


def create_base_pq_message(domain_separator, current_eth_address, base_eth_message, v, r, s, pq_nonce):
    """
    Create base PQ message for unregistration intent
    Format: DOMAIN_SEPARATOR + "Intent to unregister from Epervier Fingerprint from address " + currentEthAddress + baseETHMessage + v + r + s + pqNonce
    This is signed by the PQ key
    """
    pattern = b"Intent to unregister from Epervier Fingerprint from address "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(current_eth_address[2:]) +  # Remove "0x" prefix
        base_eth_message +
        v.to_bytes(1, 'big') +
        r.to_bytes(32, 'big') +
        s.to_bytes(32, 'big') +
        pq_nonce.to_bytes(32, 'big')
    )
    return message


def sign_with_eth_key(message_bytes, private_key, pq_fingerprint, eth_nonce):
    """Sign a message with ETH private key using EIP712"""
    # Use EIP712 structured signing for UnregistrationIntent
    struct_hash = get_unregistration_intent_struct_hash(pq_fingerprint, eth_nonce)
    
    # Create EIP712 digest with domain separator
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    digest = keccak(encode_packed(b'\x19\x01', domain_separator_bytes, struct_hash))
    
    # Sign the digest directly
    account = Account.from_key(private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}


def sign_with_pq_key(message, pq_private_key_file):
    from tempfile import NamedTemporaryFile
    import os
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(message)
        tmp.flush()
        tmp_path = tmp.name
    sign_cli = PROJECT_ROOT / "ETHFALCON/python-ref/sign_cli.py"
    privkey_path = PROJECT_ROOT / "test/test_keys" / pq_private_key_file
    venv_python = PROJECT_ROOT / "ETHFALCON/python-ref/myenv/bin/python3"
    cmd = [
        str(venv_python), str(sign_cli), "sign",
        f"--privkey={privkey_path}",
        f"--data={message.hex()}",
        "--version=epervier"
    ]
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    os.unlink(tmp_path)
    print("PQ sign_cli output:")
    print(result.stdout)
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


def generate_unregistration_revert_vectors():
    """Generate unregistration revert vectors with controlled errors"""
    print("Starting unregistration revert vector generation...")
    actors = load_actors_config()
    print(f"Loaded {len(actors)} actors from config")
    
    # Use Alice as the base actor for all revert scenarios
    alice = actors["alice"]
    bob = actors["bob"]
    charlie = actors["charlie"]
    
    vectors = []
    
    # Vector 0: Malformed message (wrong pattern)
    print("Generating vector 0: Malformed message")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, alice["pq_fingerprint"], 2)
    eth_signature = sign_with_eth_key(base_eth_message, alice["eth_private_key"], alice["pq_fingerprint"], 2)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    # Create malformed PQ message with wrong pattern
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    malformed_pq_message = (
        domain_separator_bytes +
        b"WRONG PATTERN " +  # Wrong pattern
        bytes.fromhex(alice["eth_address"][2:]) +
        base_eth_message +
        v.to_bytes(1, 'big') +
        r.to_bytes(32, 'big') +
        s.to_bytes(32, 'big') +
        (2).to_bytes(32, 'big')  # pq_nonce
    )
    
    pq_sig = sign_with_pq_key(malformed_pq_message, alice["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "Malformed message - wrong pattern",
            "pq_message": malformed_pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 1: Invalid ETH signature (malformed signature)
    print("Generating vector 1: Invalid ETH signature")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, alice["pq_fingerprint"], 2)
    eth_signature = sign_with_eth_key(base_eth_message, alice["eth_private_key"], alice["pq_fingerprint"], 2)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    # Corrupt the ETH signature by setting r to 0 (invalid signature)
    corrupted_r = 0  # This will cause ECDSA verification to fail
    
    pq_message = create_base_pq_message(
        domain_separator_bytes, alice["eth_address"], base_eth_message,
        v, corrupted_r, s, 2)
    
    pq_sig = sign_with_pq_key(pq_message, alice["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "Invalid ETH signature - malformed signature",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 2: Invalid PQ signature (malformed signature)
    print("Generating vector 2: Invalid PQ signature")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, alice["pq_fingerprint"], 2)
    eth_signature = sign_with_eth_key(base_eth_message, alice["eth_private_key"], alice["pq_fingerprint"], 2)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    pq_message = create_base_pq_message(
        domain_separator_bytes, alice["eth_address"], base_eth_message,
        v, r, s, 2)
    
    # Sign with Alice's PQ key to get a valid signature, then corrupt it
    pq_sig = sign_with_pq_key(pq_message, alice["pq_private_key_file"])
    if pq_sig:
        # Corrupt the signature by making cs1 values extremely large (should cause "norm too large" error)
        corrupted_cs1 = []
        for x in pq_sig["cs1"]:
            # Make the values extremely large to trigger norm validation failure
            corrupted_cs1.append(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        
        vectors.append({
            "description": "Invalid PQ signature - malformed signature (corrupted cs1 values)",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in corrupted_cs1],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 3: ETH address not registered (Charlie's address)
    print("Generating vector 3: ETH address not registered")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, charlie["pq_fingerprint"], 2)
    eth_signature = sign_with_eth_key(base_eth_message, charlie["eth_private_key"], charlie["pq_fingerprint"], 2)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    pq_message = create_base_pq_message(
        domain_separator_bytes, charlie["eth_address"], base_eth_message,
        v, r, s, 2)
    
    pq_sig = sign_with_pq_key(pq_message, charlie["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "ETH address not registered - Charlie's address",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 4: Change ETH intent open (valid unregistration intent - contract checks pending change intent)
    print("Generating vector 4: Change ETH intent open")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, alice["pq_fingerprint"], 2)
    eth_signature = sign_with_eth_key(base_eth_message, alice["eth_private_key"], alice["pq_fingerprint"], 2)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    pq_message = create_base_pq_message(
        domain_separator_bytes, alice["eth_address"], base_eth_message,
        v, r, s, 2)
    
    pq_sig = sign_with_pq_key(pq_message, alice["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "Change ETH intent open - valid unregistration intent (contract checks pending change intent)",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 5: PQ fingerprint not registered (Charlie's fingerprint)
    print("Generating vector 5: PQ fingerprint not registered")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, charlie["pq_fingerprint"], 2)
    eth_signature = sign_with_eth_key(base_eth_message, charlie["eth_private_key"], charlie["pq_fingerprint"], 2)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    pq_message = create_base_pq_message(
        domain_separator_bytes, charlie["eth_address"], base_eth_message,
        v, r, s, 2)
    
    pq_sig = sign_with_pq_key(pq_message, charlie["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "PQ fingerprint not registered - Charlie's fingerprint",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 6: Wrong ETH nonce (use nonce 0 instead of 2)
    print("Generating vector 6: Wrong ETH nonce")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, alice["pq_fingerprint"], 0)  # Wrong nonce
    eth_signature = sign_with_eth_key(base_eth_message, alice["eth_private_key"], alice["pq_fingerprint"], 0)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    pq_message = create_base_pq_message(
        domain_separator_bytes, alice["eth_address"], base_eth_message,
        v, r, s, 2)
    
    pq_sig = sign_with_pq_key(pq_message, alice["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "Wrong ETH nonce - using nonce 0 instead of 2",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 7: Wrong PQ nonce (use nonce 0 instead of 2)
    print("Generating vector 7: Wrong PQ nonce")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, alice["pq_fingerprint"], 2)
    eth_signature = sign_with_eth_key(base_eth_message, alice["eth_private_key"], alice["pq_fingerprint"], 2)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    pq_message = create_base_pq_message(
        domain_separator_bytes, alice["eth_address"], base_eth_message,
        v, r, s, 0)  # Wrong PQ nonce
    
    pq_sig = sign_with_pq_key(pq_message, alice["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "Wrong PQ nonce - using nonce 0 instead of 2",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 8: Pending intent exists (valid unregistration intent - contract checks pending intent)
    print("Generating vector 8: Pending intent exists")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, alice["pq_fingerprint"], 2)
    eth_signature = sign_with_eth_key(base_eth_message, alice["eth_private_key"], alice["pq_fingerprint"], 2)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    pq_message = create_base_pq_message(
        domain_separator_bytes, alice["eth_address"], base_eth_message,
        v, r, s, 2)
    
    pq_sig = sign_with_pq_key(pq_message, alice["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "Pending intent exists - valid unregistration intent (contract checks pending intent)",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 9: Wrong domain separator
    print("Generating vector 9: Wrong domain separator")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, alice["pq_fingerprint"], 2)
    eth_signature = sign_with_eth_key(base_eth_message, alice["eth_private_key"], alice["pq_fingerprint"], 2)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    # Use wrong domain separator
    wrong_domain = b'\x00' * 32  # All zeros instead of correct domain
    pq_message = create_base_pq_message(
        wrong_domain, alice["eth_address"], base_eth_message,
        v, r, s, 2)
    
    pq_sig = sign_with_pq_key(pq_message, alice["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "Wrong domain separator - using all zeros",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 10: Wrong ETH signer (Bob signs Alice's message)
    print("Generating vector 10: Wrong ETH signer")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, alice["pq_fingerprint"], 2)
    # Bob signs Alice's message
    eth_signature = sign_with_eth_key(base_eth_message, bob["eth_private_key"], alice["pq_fingerprint"], 2)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    pq_message = create_base_pq_message(
        domain_separator_bytes, alice["eth_address"], base_eth_message,
        v, r, s, 2)
    
    pq_sig = sign_with_pq_key(pq_message, alice["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "Wrong ETH signer - Bob signs Alice's message",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 11: Wrong PQ signer (Bob's PQ key signs Alice's message)
    print("Generating vector 11: Wrong PQ signer")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, alice["pq_fingerprint"], 2)
    eth_signature = sign_with_eth_key(base_eth_message, alice["eth_private_key"], alice["pq_fingerprint"], 2)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    pq_message = create_base_pq_message(
        domain_separator_bytes, alice["eth_address"], base_eth_message,
        v, r, s, 2)
    
    # Bob's PQ key signs Alice's message
    pq_sig = sign_with_pq_key(pq_message, bob["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "Wrong PQ signer - Bob's PQ key signs Alice's message",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 12: ETH address mismatch (Alice's PQ, Bob's ETH address)
    print("Generating vector 12: ETH address mismatch")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, alice["pq_fingerprint"], 2)
    eth_signature = sign_with_eth_key(base_eth_message, alice["eth_private_key"], alice["pq_fingerprint"], 2)
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    # Use Bob's ETH address instead of Alice's
    pq_message = create_base_pq_message(
        domain_separator_bytes, bob["eth_address"], base_eth_message,
        v, r, s, 2)
    
    pq_sig = sign_with_pq_key(pq_message, alice["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "ETH address mismatch - Alice's PQ, Bob's ETH address",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    # Vector 13: PQ fingerprint mismatch (Bob's PQ fingerprint, Alice's ETH address)
    print("Generating vector 13: PQ fingerprint mismatch")
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, bob["pq_fingerprint"], 2)  # Bob's fingerprint
    eth_signature = sign_with_eth_key(base_eth_message, bob["eth_private_key"], bob["pq_fingerprint"], 2)  # Bob signs his own message
    v, r, s = eth_signature["v"], eth_signature["r"], eth_signature["s"]
    
    # Use Alice's ETH address with Bob's PQ fingerprint (this creates the mismatch)
    pq_message = create_base_pq_message(
        domain_separator_bytes, alice["eth_address"], base_eth_message,
        v, r, s, 2)
    
    pq_sig = sign_with_pq_key(pq_message, bob["pq_private_key_file"])
    if pq_sig:
        vectors.append({
            "description": "PQ fingerprint mismatch - Bob's PQ fingerprint, Alice's ETH address",
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            }
        })
    
    return vectors


def main():
    """Main function to generate and save test vectors"""
    print("Generating unregistration revert test vectors...")
    
    try:
        vectors = generate_unregistration_revert_vectors()
        
        # Save to JSON file
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_PATH, 'w') as f:
            json.dump({"submit_unregistration_intent": vectors}, f, indent=2)
        print(f"Wrote {len(vectors)} unregistration revert vectors to {OUTPUT_PATH}")
        
        # Print sample vector for verification
        if vectors:
            print("\nSample unregistration revert vector:")
            sample = vectors[0]
            print(f"Description: {sample['description']}")
            print(f"PQ Message Length: {len(bytes.fromhex(sample['pq_message']))}")
            print(f"PQ Signature Salt: {sample['pq_signature']['salt']}")
            print(f"PQ Signature Hint: {sample['pq_signature']['hint']}")
        
    except Exception as e:
        print(f"Error generating vectors: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
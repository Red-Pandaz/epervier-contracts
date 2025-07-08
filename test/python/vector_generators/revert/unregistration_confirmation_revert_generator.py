#!/usr/bin/env python3

import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))  # Add python directory to path
from eip712_helpers import get_unregistration_confirmation_struct_hash, encode_packed
from eip712_config import DOMAIN_SEPARATOR

# Get the project root directory
project_root = Path(__file__).resolve().parents[4]
ACTORS_CONFIG_PATH = project_root / "test" / "test_keys" / "actors_config.json"
OUTPUT_PATH = project_root / "test/test_vectors/revert/unregistration_confirmation_revert_vectors.json"
domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')

def load_actors_config():
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]

def build_base_pq_unregistration_confirm_message(domain_separator, eth_address, pq_nonce):
    pattern = b"Confirm unregistration from ETH Address "
    return domain_separator + pattern + bytes.fromhex(eth_address[2:]) + int_to_bytes32(pq_nonce)

def create_eth_confirm_message(domain_separator, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    pattern = b"Confirm unregistration from Epervier Fingerprint "
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    message = (
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +
        base_pq_message +
        salt +
        pack_uint256_array(cs1) +
        pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') +
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def sign_with_pq_key(base_pq_message, pq_private_key_file):
    from tempfile import NamedTemporaryFile
    import os
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(base_pq_message)
        tmp.flush()
        tmp_path = tmp.name
    sign_cli = project_root / "ETHFALCON/python-ref/sign_cli.py"
    privkey_path = project_root / "test/test_keys" / pq_private_key_file
    venv_python = project_root / "ETHFALCON/python-ref/myenv/bin/python3"
    cmd = [
        str(venv_python), str(sign_cli), "sign",
        f"--privkey={privkey_path}",
        f"--data={base_pq_message.hex()}",
        "--version=epervier"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    os.unlink(tmp_path)
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

def sign_with_eth_key(eth_message, eth_private_key, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    struct_hash = get_unregistration_confirmation_struct_hash(pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce)
    digest = keccak(encode_packed(b'\x19\x01', domain_separator_bytes, struct_hash))
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}

def make_json_safe_vector(vec):
    # Convert all bytes fields to hex strings, and recursively handle dicts/lists
    def safe(val):
        if isinstance(val, bytes):
            return val.hex()
        elif isinstance(val, dict):
            return {k: safe(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [safe(x) for x in val]
        else:
            return val
    return {k: safe(v) for k, v in vec.items()}

def main():
    print("Starting unregistration confirmation revert vector generation...")
    actors = load_actors_config()
    alice = actors["alice"]
    bob = actors["bob"]
    charlie = actors["charlie"]
    vectors = []
    # 1. Valid vector as template
    pq_nonce = 3
    eth_nonce = 3
    base_pq_message = build_base_pq_unregistration_confirm_message(domain_separator_bytes, alice["eth_address"], pq_nonce)
    pq_sig = sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])
    eth_message = create_eth_confirm_message(domain_separator_bytes, alice["pq_fingerprint"], base_pq_message, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce)
    eth_signature = sign_with_eth_key(eth_message, alice["eth_private_key"], alice["pq_fingerprint"], base_pq_message, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce)
    valid_vector = {
        "actor": "alice",
        "eth_address": alice["eth_address"],
        "pq_fingerprint": alice["pq_fingerprint"],
        "base_pq_message": base_pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"].hex(),
            "cs1": [hex(x) for x in pq_sig["cs1"]],
            "cs2": [hex(x) for x in pq_sig["cs2"]],
            "hint": pq_sig["hint"]
        },
        "eth_message": eth_message.hex(),
        "eth_signature": eth_signature,
        "eth_nonce": eth_nonce,
        "pq_nonce": pq_nonce
    }
    # 2. Now create 12 vectors, each with a single malformation
    # Vector 0: Malformed PQ message (truncated)
    v0 = valid_vector.copy()
    v0["description"] = "Malformed PQ message (truncated)"
    truncated_pq_message = base_pq_message[:60]
    # Regenerate ETH message with truncated PQ message
    eth_message_truncated = create_eth_confirm_message(
        domain_separator_bytes,
        alice["pq_fingerprint"],
        truncated_pq_message,
        pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"],
        eth_nonce
    )
    # Regenerate ETH signature for truncated message
    eth_signature_truncated = sign_with_eth_key(eth_message_truncated, alice["eth_private_key"], alice["pq_fingerprint"], truncated_pq_message, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce)
    v0["base_pq_message"] = truncated_pq_message.hex()
    v0["eth_message"] = eth_message_truncated.hex()
    v0["eth_signature"] = eth_signature_truncated
    vectors.append(v0)
    # Vector 1: Invalid ETH signature (all zeroes)
    v1 = valid_vector.copy()
    v1["description"] = "Invalid ETH signature (all zeroes)"
    v1["eth_signature"] = {"v": 27, "r": 0, "s": 0}
    vectors.append(v1)
    # Vector 2: Invalid PQ signature (cs1 all max)
    v2 = valid_vector.copy()
    v2["description"] = "Invalid PQ signature (cs1 all max)"
    pq_sig2 = pq_sig.copy()
    pq_sig2["cs1"] = [0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF] * 32
    # Regenerate ETH message with invalid PQ signature
    eth_message_invalid = create_eth_confirm_message(
        domain_separator_bytes,
        alice["pq_fingerprint"],
        base_pq_message,
        pq_sig2["salt"], pq_sig2["cs1"], pq_sig2["cs2"], pq_sig2["hint"],
        eth_nonce
    )
    # Regenerate ETH signature for invalid PQ signature
    eth_signature_invalid = sign_with_eth_key(eth_message_invalid, alice["eth_private_key"], alice["pq_fingerprint"], base_pq_message, pq_sig2["salt"], pq_sig2["cs1"], pq_sig2["cs2"], pq_sig2["hint"], eth_nonce)
    v2["pq_signature"] = {
        "salt": pq_sig["salt"].hex(),
        "cs1": [hex(x) for x in pq_sig2["cs1"]],
        "cs2": [hex(x) for x in pq_sig["cs2"]],
        "hint": pq_sig["hint"]
    }
    v2["eth_message"] = eth_message_invalid.hex()
    v2["eth_signature"] = eth_signature_invalid
    vectors.append(v2)
    # Vector 3: No pending intent (Charlie's address)
    v3 = valid_vector.copy()
    v3["description"] = "No pending intent (Charlie's address)"
    v3["eth_address"] = charlie["eth_address"]
    v3["pq_fingerprint"] = charlie["pq_fingerprint"]
    vectors.append(v3)
    # Vector 4: Wrong ETH nonce (eth_nonce + 1)
    v4 = valid_vector.copy()
    v4["description"] = "Wrong ETH nonce (eth_nonce + 1)"
    eth_nonce_wrong = eth_nonce + 1
    # ETH message with wrong nonce
    eth_message_wrong = create_eth_confirm_message(
        domain_separator_bytes,
        alice["pq_fingerprint"],
        base_pq_message,
        pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"],
        eth_nonce_wrong
    )
    eth_signature_wrong = sign_with_eth_key(eth_message_wrong, alice["eth_private_key"], alice["pq_fingerprint"], base_pq_message, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce_wrong)
    v4["eth_message"] = eth_message_wrong.hex()
    v4["eth_signature"] = eth_signature_wrong
    v4["eth_nonce"] = eth_nonce_wrong
    vectors.append(v4)

    # Vector 5: Wrong PQ nonce (pq_nonce + 1)
    v5 = valid_vector.copy()
    v5["description"] = "Wrong PQ nonce (pq_nonce + 1)"
    pq_nonce_wrong = pq_nonce + 1
    # PQ message and signature with wrong nonce
    base_pq_message_wrong = build_base_pq_unregistration_confirm_message(domain_separator_bytes, alice["eth_address"], pq_nonce_wrong)
    pq_sig_wrong = sign_with_pq_key(base_pq_message_wrong, alice["pq_private_key_file"])
    # ETH message with wrong PQ message/signature
    eth_message_wrong = create_eth_confirm_message(
        domain_separator_bytes,
        alice["pq_fingerprint"],
        base_pq_message_wrong,
        pq_sig_wrong["salt"], pq_sig_wrong["cs1"], pq_sig_wrong["cs2"], pq_sig_wrong["hint"],
        eth_nonce
    )
    eth_signature_wrong = sign_with_eth_key(eth_message_wrong, alice["eth_private_key"], alice["pq_fingerprint"], base_pq_message_wrong, pq_sig_wrong["salt"], pq_sig_wrong["cs1"], pq_sig_wrong["cs2"], pq_sig_wrong["hint"], eth_nonce)
    v5["base_pq_message"] = base_pq_message_wrong.hex()
    v5["pq_signature"] = {
        "salt": pq_sig_wrong["salt"].hex(),
        "cs1": [hex(x) for x in pq_sig_wrong["cs1"]],
        "cs2": [hex(x) for x in pq_sig_wrong["cs2"]],
        "hint": pq_sig_wrong["hint"]
    }
    v5["eth_message"] = eth_message_wrong.hex()
    v5["eth_signature"] = eth_signature_wrong
    v5["pq_nonce"] = pq_nonce_wrong
    vectors.append(v5)

    # Vector 6: Fingerprint mismatch (Bob's fingerprint in ETH message, Alice's PQ signature)
    v6 = valid_vector.copy()
    v6["description"] = "Fingerprint mismatch (Bob's fingerprint in ETH message, Alice's PQ signature)"
    # Build PQ message and signature as Alice (normal)
    base_pq_message = build_base_pq_unregistration_confirm_message(domain_separator_bytes, alice["eth_address"], pq_nonce)
    pq_sig = sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])  # Alice's key
    # Build ETH message with Bob's fingerprint (mismatch)
    eth_message = create_eth_confirm_message(
        domain_separator_bytes,
        bob["pq_fingerprint"],  # Bob's fingerprint in ETH message
        base_pq_message,
        pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"],
        eth_nonce
    )
    # Sign ETH message with Alice's ETH key
    eth_signature = sign_with_eth_key(eth_message, alice["eth_private_key"], bob["pq_fingerprint"], base_pq_message, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce)
    v6["eth_message"] = eth_message.hex()
    v6["eth_signature"] = eth_signature
    v6["base_pq_message"] = base_pq_message.hex()
    v6["pq_signature"] = {
        "salt": pq_sig["salt"].hex(),
        "cs1": [hex(x) for x in pq_sig["cs1"]],
        "cs2": [hex(x) for x in pq_sig["cs2"]],
        "hint": pq_sig["hint"]
    }
    v6["pq_fingerprint"] = alice["pq_fingerprint"]  # Alice's fingerprint (recovered from PQ signature)
    vectors.append(v6)
    # Vector 7: Wrong domain separator in PQ message (all zeros)
    v7 = valid_vector.copy()
    v7["description"] = "Wrong domain separator in PQ message (all zeros)"
    # Build PQ message with wrong domain separator
    base_pq_message_wrong = build_base_pq_unregistration_confirm_message(b'\x00'*32, alice["eth_address"], pq_nonce)
    pq_sig_wrong = sign_with_pq_key(base_pq_message_wrong, alice["pq_private_key_file"])
    # Build ETH message with the wrong PQ message
    eth_message_wrong = create_eth_confirm_message(
        domain_separator_bytes,
        alice["pq_fingerprint"],
        base_pq_message_wrong,
        pq_sig_wrong["salt"], pq_sig_wrong["cs1"], pq_sig_wrong["cs2"], pq_sig_wrong["hint"],
        eth_nonce
    )
    # Sign ETH message with Alice's ETH key
    eth_signature_wrong = sign_with_eth_key(eth_message_wrong, alice["eth_private_key"], alice["pq_fingerprint"], base_pq_message_wrong, pq_sig_wrong["salt"], pq_sig_wrong["cs1"], pq_sig_wrong["cs2"], pq_sig_wrong["hint"], eth_nonce)
    v7["eth_message"] = eth_message_wrong.hex()
    v7["eth_signature"] = eth_signature_wrong
    v7["base_pq_message"] = base_pq_message_wrong.hex()
    v7["pq_signature"] = {
        "salt": pq_sig_wrong["salt"].hex(),
        "cs1": [hex(x) for x in pq_sig_wrong["cs1"]],
        "cs2": [hex(x) for x in pq_sig_wrong["cs2"]],
        "hint": pq_sig_wrong["hint"]
    }
    vectors.append(v7)
    # Vector 8: Wrong ETH signer (Bob's key)
    v8 = valid_vector.copy()
    v8["description"] = "Wrong ETH signer (Bob's key)"
    v8["eth_signature"] = sign_with_eth_key(eth_message, bob["eth_private_key"], alice["pq_fingerprint"], base_pq_message, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce)
    vectors.append(v8)
    # Vector 9: Wrong PQ signer (Bob's PQ key)
    v9 = valid_vector.copy()
    v9["description"] = "Wrong PQ signer (Bob's PQ key)"
    pq_sig9 = sign_with_pq_key(base_pq_message, bob["pq_private_key_file"])
    # Regenerate ETH message with Bob's PQ signature
    eth_message_bob_pq = create_eth_confirm_message(
        domain_separator_bytes,
        alice["pq_fingerprint"],
        base_pq_message,
        pq_sig9["salt"], pq_sig9["cs1"], pq_sig9["cs2"], pq_sig9["hint"],
        eth_nonce
    )
    # Regenerate ETH signature for Bob's PQ signature
    eth_signature_bob_pq = sign_with_eth_key(eth_message_bob_pq, alice["eth_private_key"], alice["pq_fingerprint"], base_pq_message, pq_sig9["salt"], pq_sig9["cs1"], pq_sig9["cs2"], pq_sig9["hint"], eth_nonce)
    v9["pq_signature"] = {
        "salt": pq_sig9["salt"].hex(),
        "cs1": [hex(x) for x in pq_sig9["cs1"]],
        "cs2": [hex(x) for x in pq_sig9["cs2"]],
        "hint": pq_sig9["hint"]
    }
    v9["eth_message"] = eth_message_bob_pq.hex()
    v9["eth_signature"] = eth_signature_bob_pq
    vectors.append(v9)
    # Vector 10: ETH address mismatch (Bob's address in PQ message, Bob's fingerprint in ETH message)
    v10 = valid_vector.copy()
    v10["description"] = "ETH address mismatch (Bob's address in PQ message, Bob's fingerprint in ETH message)"
    # Build PQ message with Bob's address and Bob's signature
    base_pq_message_bob = build_base_pq_unregistration_confirm_message(domain_separator_bytes, bob["eth_address"], pq_nonce)
    pq_sig_bob = sign_with_pq_key(base_pq_message_bob, bob["pq_private_key_file"])  # Bob's key
    # Build ETH message with Bob's fingerprint
    eth_message_bob = create_eth_confirm_message(
        domain_separator_bytes,
        bob["pq_fingerprint"],  # Bob's fingerprint in ETH message
        base_pq_message_bob,
        pq_sig_bob["salt"], pq_sig_bob["cs1"], pq_sig_bob["cs2"], pq_sig_bob["hint"],
        eth_nonce
    )
    # Sign ETH message with Alice's ETH key
    eth_signature_alice = sign_with_eth_key(eth_message_bob, alice["eth_private_key"], bob["pq_fingerprint"], base_pq_message_bob, pq_sig_bob["salt"], pq_sig_bob["cs1"], pq_sig_bob["cs2"], pq_sig_bob["hint"], eth_nonce)
    v10["eth_message"] = eth_message_bob.hex()
    v10["eth_signature"] = eth_signature_alice
    v10["base_pq_message"] = base_pq_message_bob.hex()
    v10["pq_signature"] = {
        "salt": pq_sig_bob["salt"].hex(),
        "cs1": [hex(x) for x in pq_sig_bob["cs1"]],
        "cs2": [hex(x) for x in pq_sig_bob["cs2"]],
        "hint": pq_sig_bob["hint"]
    }
    v10["pq_fingerprint"] = bob["pq_fingerprint"]  # Bob's fingerprint in the vector
    vectors.append(v10)
    # Vector 11: PQ fingerprint mismatch (Bob's fingerprint in ETH message)
    v11 = valid_vector.copy()
    v11["description"] = "PQ fingerprint mismatch (Bob's fingerprint in ETH message)"
    # Generate NEW PQ signature with Bob's key
    base_pq_message_bob = build_base_pq_unregistration_confirm_message(domain_separator_bytes, alice["eth_address"], pq_nonce)
    pq_sig_bob = sign_with_pq_key(base_pq_message_bob, bob["pq_private_key_file"])  # Bob's key
    # Regenerate ETH message with Alice's fingerprint
    eth_message_alice = create_eth_confirm_message(
        domain_separator_bytes,
        alice["pq_fingerprint"],  # Alice's fingerprint in ETH message
        base_pq_message_bob,
        pq_sig_bob["salt"], pq_sig_bob["cs1"], pq_sig_bob["cs2"], pq_sig_bob["hint"], eth_nonce
    )
    # Regenerate ETH signature for the new message
    eth_signature_alice = sign_with_eth_key(eth_message_alice, alice["eth_private_key"], alice["pq_fingerprint"], base_pq_message_bob, pq_sig_bob["salt"], pq_sig_bob["cs1"], pq_sig_bob["cs2"], pq_sig_bob["hint"], eth_nonce)
    v11["eth_message"] = eth_message_alice.hex()
    v11["eth_signature"] = eth_signature_alice
    v11["base_pq_message"] = base_pq_message_bob.hex()
    v11["pq_signature"] = {
        "salt": pq_sig_bob["salt"].hex(),
        "cs1": [hex(x) for x in pq_sig_bob["cs1"]],
        "cs2": [hex(x) for x in pq_sig_bob["cs2"]],
        "hint": pq_sig_bob["hint"]
    }
    v11["pq_fingerprint"] = bob["pq_fingerprint"]
    vectors.append(v11)
    # Vector 12: Wrong domain separator in EIP712 signature (all zeros)
    v12 = valid_vector.copy()
    v12["description"] = "Wrong domain separator in EIP712 signature (all zeros)"
    # Create ETH signature with wrong domain separator
    struct_hash = get_unregistration_confirmation_struct_hash(alice["pq_fingerprint"], base_pq_message, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce)
    digest = keccak(encode_packed(b'\x19\x01', b'\x00'*32, struct_hash))  # Wrong domain separator
    account = Account.from_key(alice["eth_private_key"])
    sig = Account._sign_hash(digest, private_key=account.key)
    v12["eth_signature"] = {"v": sig.v, "r": sig.r, "s": sig.s}
    vectors.append(v12)
    # Write to file
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    safe_vectors = [make_json_safe_vector(v) for v in vectors]
    output_data = {
        "confirm_unregistration_intent": safe_vectors
    }
    with open(OUTPUT_PATH, 'w') as f:
        json.dump(output_data, f, indent=2)
    print(f"Wrote {len(safe_vectors)} confirm_unregistration_intent vectors to {OUTPUT_PATH}")

if __name__ == "__main__":
    main() 
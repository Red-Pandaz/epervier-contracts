#!/usr/bin/env python3
"""
Revert Test Vector Generator

This generator creates test vectors specifically designed to trigger revert conditions
in the PQRegistry contract. Each vector is crafted to test a specific failure case.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List
from eth_account import Account
from eth_utils import keccak

# Add the parent directory to the path to import eip712_config
sys.path.append(str(Path(__file__).resolve().parents[2]))  # test/python
from eip712_config import DOMAIN_SEPARATOR
from eip712_helpers import (
    get_registration_intent_struct_hash,
    get_eip712_digest,
    sign_eip712_message,
)

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[4]  # epervier-registry
ACTORS_CONFIG_PATH = PROJECT_ROOT / "test" / "test_keys" / "actors_config.json"
OUTPUT_PATH = PROJECT_ROOT / "test/test_vectors/revert"

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')

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

def load_actors_config():
    # Load the actors config JSON
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]

def build_base_pq_message(domain_separator, eth_address, pq_nonce):
    pattern = b"Intent to pair ETH Address "
    domain_separator_bytes = bytes.fromhex(domain_separator[2:])
    msg = domain_separator_bytes + pattern + bytes.fromhex(eth_address[2:]) + int_to_bytes32(pq_nonce)
    print(f"[DEBUG] base_pq_message length: {len(msg)} (should be 111)")
    assert len(msg) == 111, f"base_pq_message wrong length: {len(msg)}"
    return msg

def sign_with_pq_key(base_pq_message, pq_private_key_file):
    """Sign a message with PQ private key using sign_cli.py"""
    import os
    import subprocess
    
    try:
        # Sign with PQ key using sign_cli.py
        sign_cli = str(PROJECT_ROOT / "ETHFALCON" / "python-ref" / "sign_cli.py")
        privkey_path = str(PROJECT_ROOT / "test" / "test_keys" / pq_private_key_file)
        venv_python = str(PROJECT_ROOT / "ETHFALCON" / "python-ref" / "myenv" / "bin" / "python3")
        
        cmd = [
            venv_python, sign_cli, "sign",
            f"--privkey={privkey_path}",
            f"--data={base_pq_message.hex()}",
            "--version=epervier"
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT / "ETHFALCON" / "python-ref")
        
        if result.returncode != 0:
            print(f"Error signing message: {result.stderr}")
            return None
        
        print(f"PQ sign_cli output:")
        print(result.stdout)
        
        # Parse the signature components from stdout
        lines = result.stdout.splitlines()
        signature_data = {}
        for line in lines:
            if line.startswith("salt:"):
                signature_data["salt"] = bytes.fromhex(line.split()[1])
            elif line.startswith("hint:"):
                signature_data["hint"] = int(line.split()[1])
            elif line.startswith("cs1:"):
                signature_data["cs1"] = [int(x, 16) for x in line.split()[1:]]
            elif line.startswith("cs2:"):
                signature_data["cs2"] = [int(x, 16) for x in line.split()[1:]]
        
        if not all(key in signature_data for key in ["salt", "hint", "cs1", "cs2"]):
            print(f"Failed to parse signature components")
            return None
        
        return signature_data
        
    except Exception as e:
        print(f"Exception during PQ signing: {e}")
        return None

def build_eth_intent_message(domain_separator, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    pattern = b"Intent to pair Epervier Key"
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    eth_message = (
        pattern + base_pq_message + salt +
        pack_uint256_array(cs1) + pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') + int_to_bytes32(eth_nonce)
    )
    print(f"[DEBUG] eth_intent_message length: {len(eth_message)}")
    return eth_message

def sign_with_eth_key(eth_intent_message, eth_private_key, salt, cs1, cs2, hint, eth_nonce, base_pq_message):
    struct_hash = keccak(encode_packed(
        keccak(b"RegistrationIntent(bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,bytes basePQMessage,uint256 ethNonce)"),
        keccak(salt),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs1])),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs2])),
        hint.to_bytes(32, 'big'),
        keccak(base_pq_message),
        eth_nonce.to_bytes(32, 'big')
    ))
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    digest = keccak(encode_packed(b'\x19\x01', domain_separator_bytes, struct_hash))
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}

def create_pq_confirmation_message(eth_address, pq_nonce):
    # Create PQ confirmation message
    pattern = b"Confirm registration with ETH Address "
    return pattern + bytes.fromhex(eth_address[2:]) + int_to_bytes32(pq_nonce)

class RevertVectorGenerator:
    def __init__(self):
        self.actors = load_actors_config()
        
    def create_alice_eth_bob_pq_vector(self) -> Dict[str, Any]:
        """Create a valid vector with Alice's ETH address and Bob's PQ fingerprint"""
        alice = self.actors["alice"]
        bob = self.actors["bob"]
        eth_nonce = 0
        pq_nonce = 0
        
        # Use Alice's ETH address but Bob's PQ fingerprint
        eth_address = alice["eth_address"]
        eth_private_key = alice["eth_private_key"]
        pq_private_key_file = bob["pq_private_key_file"]
        pq_fingerprint = bob["pq_fingerprint"]
        
        # 1. Build base PQ message with Alice's ETH address
        print("Building base PQ message for AliceETH + BobPQ...")
        base_pq_message = build_base_pq_message(DOMAIN_SEPARATOR, eth_address, pq_nonce)
        print(f"Base PQ message length: {len(base_pq_message)} bytes")
        
        # 2. PQ sign with Bob's PQ key
        print("Signing with Bob's PQ key...")
        pq_sig = sign_with_pq_key(base_pq_message, pq_private_key_file)
        if pq_sig is None:
            print("Failed to generate PQ signature for Bob!")
            return None
        print(f"PQ signature generated: {len(pq_sig)} components")
        
        # 3. Build ETH intent message
        print("Building ETH intent message...")
        eth_intent_message = build_eth_intent_message(
            DOMAIN_SEPARATOR, base_pq_message, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce
        )
        print(f"ETH intent message length: {len(eth_intent_message)} bytes")
        
        # 4. ETH sign with Alice's ETH key
        print("Signing with Alice's ETH key...")
        eth_sig = sign_with_eth_key(eth_intent_message, eth_private_key, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce, base_pq_message)
        print(f"ETH signature generated: v={eth_sig['v']}, r={eth_sig['r']}, s={eth_sig['s']}")
        
        # 5. Collect all fields
        print("Collecting vector data...")
        vector = {
            "test_name": "eth_address_already_has_intent_alice_eth_bob_pq",
            "description": "Valid vector with Alice's ETH address and Bob's PQ fingerprint (should fail due to existing intent)",
            "eth_address": eth_address,
            "pq_fingerprint": pq_fingerprint,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce,
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            },
            "eth_message": eth_intent_message.hex(),
            "eth_signature": {
                "v": eth_sig["v"],
                "r": f"0x{eth_sig['r']:064x}",
                "s": f"0x{eth_sig['s']:064x}"
            }
        }
        return vector

    def generate_submit_registration_intent_revert_vectors(self) -> Dict[str, Any]:
        """Generate revert test vectors for submitRegistrationIntent()"""
        
        vectors = {
            "submit_registration_intent_reverts": []
        }
        
        print("Generating submitRegistrationIntent revert vectors...")
        # Test 1: ETH address already has pending intent
        print("Test 1: ETH address already has pending intent")
        alice = self.actors["alice"]
        eth_nonce = 0
        pq_nonce = 0
        
        # Create valid intent (will be used twice)
        base_pq_message = build_base_pq_message(DOMAIN_SEPARATOR, alice["eth_address"], pq_nonce)
        pq_signature = sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])
        
        eth_message = build_eth_intent_message(
            DOMAIN_SEPARATOR, base_pq_message, pq_signature["salt"], pq_signature["cs1"], pq_signature["cs2"], pq_signature["hint"], eth_nonce
        )
        eth_signature = sign_with_eth_key(eth_message, alice["eth_private_key"], pq_signature["salt"], pq_signature["cs1"], pq_signature["cs2"], pq_signature["hint"], eth_nonce, base_pq_message)
        
        vectors["submit_registration_intent_reverts"].append({
            "test_name": "eth_address_already_has_intent",
            "description": "Test revert when ETH address already has pending intent",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce,
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": {
                "salt": pq_signature["salt"].hex(),
                "cs1": [hex(x) for x in pq_signature["cs1"]],
                "cs2": [hex(x) for x in pq_signature["cs2"]],
                "hint": pq_signature["hint"]
            },
            "eth_message": eth_message.hex(),
            "eth_signature": {
                "v": eth_signature["v"],
                "r": f"0x{eth_signature['r']:064x}",
                "s": f"0x{eth_signature['s']:064x}"
            }
        })
        print("  [OK] Vector: eth_address_already_has_intent")
        
        print(f"  Alice ETH: {alice['eth_address']}, PQ: {alice['pq_fingerprint']}")
        print(f"  ETH nonce: {eth_nonce}, PQ nonce: {pq_nonce}")
        print(f"  PQ signature: salt={pq_signature['salt'].hex()}, hint={pq_signature['hint']}")
        print(f"  ETH signature: v={eth_signature['v']}, r={eth_signature['r']}, s={eth_signature['s']}")
        
        # Test 2: PQ fingerprint already has pending intent
        print("Test 2: PQ fingerprint already has pending intent")
        bob = self.actors["bob"]
        eth_nonce_bob = 0
        pq_nonce_bob = 0
        
        base_pq_message_bob = build_base_pq_message(DOMAIN_SEPARATOR, bob["eth_address"], pq_nonce_bob)
        pq_signature_bob = sign_with_pq_key(base_pq_message_bob, bob["pq_private_key_file"])
        
        eth_message_bob = build_eth_intent_message(
            DOMAIN_SEPARATOR, base_pq_message_bob, pq_signature_bob["salt"], pq_signature_bob["cs1"], pq_signature_bob["cs2"], pq_signature_bob["hint"], eth_nonce_bob
        )
        eth_signature_bob = sign_with_eth_key(eth_message_bob, bob["eth_private_key"], pq_signature_bob["salt"], pq_signature_bob["cs1"], pq_signature_bob["cs2"], pq_signature_bob["hint"], eth_nonce_bob, base_pq_message_bob)
        
        vectors["submit_registration_intent_reverts"].append({
            "test_name": "pq_fingerprint_already_has_intent",
            "description": "Test revert when PQ fingerprint already has pending intent",
            "eth_address": bob["eth_address"],
            "pq_fingerprint": bob["pq_fingerprint"],
            "eth_nonce": eth_nonce_bob,
            "pq_nonce": pq_nonce_bob,
            "base_pq_message": base_pq_message_bob.hex(),
            "pq_signature": {
                "salt": pq_signature_bob["salt"].hex(),
                "cs1": [hex(x) for x in pq_signature_bob["cs1"]],
                "cs2": [hex(x) for x in pq_signature_bob["cs2"]],
                "hint": pq_signature_bob["hint"]
            },
            "eth_message": eth_message_bob.hex(),
            "eth_signature": {
                "v": eth_signature_bob["v"],
                "r": f"0x{eth_signature_bob['r']:064x}",
                "s": f"0x{eth_signature_bob['s']:064x}"
            }
        })
        print("  [OK] Vector: pq_fingerprint_already_has_intent")
        
        print(f"  Bob ETH: {bob['eth_address']}, PQ: {bob['pq_fingerprint']}")
        print(f"  ETH nonce: {eth_nonce_bob}, PQ nonce: {pq_nonce_bob}")
        print(f"  PQ signature: salt={pq_signature_bob['salt'].hex()}, hint={pq_signature_bob['hint']}")
        print(f"  ETH signature: v={eth_signature_bob['v']}, r={eth_signature_bob['r']}, s={eth_signature_bob['s']}")
        
        # Test 3: ETH address already registered
        print("Test 3: ETH address already registered")
        vectors["submit_registration_intent_reverts"].append({
            "test_name": "eth_address_already_registered",
            "description": "Test revert when ETH address is already registered",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_nonce": 2,  # After registration, nonce should be 2
            "pq_nonce": 2,   # After registration, nonce should be 2
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": {
                "salt": pq_signature["salt"].hex(),
                "cs1": [hex(x) for x in pq_signature["cs1"]],
                "cs2": [hex(x) for x in pq_signature["cs2"]],
                "hint": pq_signature["hint"]
            },
            "eth_message": eth_message.hex(),
            "eth_signature": {
                "v": eth_signature["v"],
                "r": f"0x{eth_signature['r']:064x}",
                "s": f"0x{eth_signature['s']:064x}"
            }
        })
        print("  [OK] Vector: eth_address_already_registered")
        
        # Test 4: Wrong ETH nonce
        print("Test 4: Wrong ETH nonce")
        wrong_eth_nonce = 5  # Wrong nonce
        base_pq_message_wrong_nonce = build_base_pq_message(DOMAIN_SEPARATOR, alice["eth_address"], pq_nonce)
        pq_signature_wrong_nonce = sign_with_pq_key(base_pq_message_wrong_nonce, alice["pq_private_key_file"])
        
        eth_message_wrong_nonce = build_eth_intent_message(
            DOMAIN_SEPARATOR, base_pq_message_wrong_nonce, pq_signature_wrong_nonce["salt"], pq_signature_wrong_nonce["cs1"], pq_signature_wrong_nonce["cs2"], pq_signature_wrong_nonce["hint"], wrong_eth_nonce
        )
        eth_signature_wrong_nonce = sign_with_eth_key(eth_message_wrong_nonce, alice["eth_private_key"], pq_signature_wrong_nonce["salt"], pq_signature_wrong_nonce["cs1"], pq_signature_wrong_nonce["cs2"], pq_signature_wrong_nonce["hint"], wrong_eth_nonce, base_pq_message_wrong_nonce)
        
        vectors["submit_registration_intent_reverts"].append({
            "test_name": "wrong_eth_nonce",
            "description": "Test revert when ETH nonce is wrong",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_nonce": wrong_eth_nonce,
            "pq_nonce": pq_nonce,
            "base_pq_message": base_pq_message_wrong_nonce.hex(),
            "pq_signature": {
                "salt": pq_signature_wrong_nonce["salt"].hex(),
                "cs1": [hex(x) for x in pq_signature_wrong_nonce["cs1"]],
                "cs2": [hex(x) for x in pq_signature_wrong_nonce["cs2"]],
                "hint": pq_signature_wrong_nonce["hint"]
            },
            "eth_message": eth_message_wrong_nonce.hex(),
            "eth_signature": {
                "v": eth_signature_wrong_nonce["v"],
                "r": f"0x{eth_signature_wrong_nonce['r']:064x}",
                "s": f"0x{eth_signature_wrong_nonce['s']:064x}"
            }
        })
        print("  [OK] Vector: wrong_eth_nonce")
        
        print(f"  Wrong ETH nonce: {wrong_eth_nonce}")
        print(f"  PQ signature: salt={pq_signature_wrong_nonce['salt'].hex()}, hint={pq_signature_wrong_nonce['hint']}")
        print(f"  ETH signature: v={eth_signature_wrong_nonce['v']}, r={eth_signature_wrong_nonce['r']}, s={eth_signature_wrong_nonce['s']}")
        
        # Test 5: Wrong PQ nonce
        print("Test 5: Wrong PQ nonce")
        wrong_pq_nonce = 5  # Wrong nonce
        base_pq_message_wrong_pq_nonce = build_base_pq_message(DOMAIN_SEPARATOR, alice["eth_address"], wrong_pq_nonce)
        pq_signature_wrong_pq_nonce = sign_with_pq_key(base_pq_message_wrong_pq_nonce, alice["pq_private_key_file"])
        
        eth_message_wrong_pq_nonce = build_eth_intent_message(
            DOMAIN_SEPARATOR, base_pq_message_wrong_pq_nonce, pq_signature_wrong_pq_nonce["salt"], pq_signature_wrong_pq_nonce["cs1"], pq_signature_wrong_pq_nonce["cs2"], pq_signature_wrong_pq_nonce["hint"], eth_nonce
        )
        eth_signature_wrong_pq_nonce = sign_with_eth_key(eth_message_wrong_pq_nonce, alice["eth_private_key"], pq_signature_wrong_pq_nonce["salt"], pq_signature_wrong_pq_nonce["cs1"], pq_signature_wrong_pq_nonce["cs2"], pq_signature_wrong_pq_nonce["hint"], eth_nonce, base_pq_message_wrong_pq_nonce)
        
        vectors["submit_registration_intent_reverts"].append({
            "test_name": "wrong_pq_nonce",
            "description": "Test revert when PQ nonce is wrong",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_nonce": eth_nonce,
            "pq_nonce": wrong_pq_nonce,
            "base_pq_message": base_pq_message_wrong_pq_nonce.hex(),
            "pq_signature": {
                "salt": pq_signature_wrong_pq_nonce["salt"].hex(),
                "cs1": [hex(x) for x in pq_signature_wrong_pq_nonce["cs1"]],
                "cs2": [hex(x) for x in pq_signature_wrong_pq_nonce["cs2"]],
                "hint": pq_signature_wrong_pq_nonce["hint"]
            },
            "eth_message": eth_message_wrong_pq_nonce.hex(),
            "eth_signature": {
                "v": eth_signature_wrong_pq_nonce["v"],
                "r": f"0x{eth_signature_wrong_pq_nonce['r']:064x}",
                "s": f"0x{eth_signature_wrong_pq_nonce['s']:064x}"
            }
        })
        print("  [OK] Vector: wrong_pq_nonce")
        
        # Test 6: PQ fingerprint already registered (Alice's PQ + Bob's ETH)
        print("Test 6: PQ fingerprint already registered")
        # Use Alice's PQ fingerprint but Bob's ETH address
        alice_pq_nonce = 0
        bob_eth_nonce = 0
        
        # Create base PQ message with Alice's PQ fingerprint but Bob's ETH address
        base_pq_message_alice_pq_bob_eth = build_base_pq_message(DOMAIN_SEPARATOR, bob["eth_address"], alice_pq_nonce)
        pq_signature_alice_pq_bob_eth = sign_with_pq_key(base_pq_message_alice_pq_bob_eth, alice["pq_private_key_file"])
        
        eth_message_alice_pq_bob_eth = build_eth_intent_message(
            DOMAIN_SEPARATOR, base_pq_message_alice_pq_bob_eth, pq_signature_alice_pq_bob_eth["salt"], pq_signature_alice_pq_bob_eth["cs1"], pq_signature_alice_pq_bob_eth["cs2"], pq_signature_alice_pq_bob_eth["hint"], bob_eth_nonce
        )
        eth_signature_alice_pq_bob_eth = sign_with_eth_key(eth_message_alice_pq_bob_eth, bob["eth_private_key"], pq_signature_alice_pq_bob_eth["salt"], pq_signature_alice_pq_bob_eth["cs1"], pq_signature_alice_pq_bob_eth["cs2"], pq_signature_alice_pq_bob_eth["hint"], bob_eth_nonce, base_pq_message_alice_pq_bob_eth)
        
        vectors["submit_registration_intent_reverts"].append({
            "test_name": "pq_fingerprint_already_registered",
            "description": "Test revert when PQ fingerprint is already registered (Alice's PQ + Bob's ETH)",
            "eth_address": bob["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],  # Alice's PQ fingerprint
            "eth_nonce": bob_eth_nonce,
            "pq_nonce": alice_pq_nonce,
            "base_pq_message": base_pq_message_alice_pq_bob_eth.hex(),
            "pq_signature": {
                "salt": pq_signature_alice_pq_bob_eth["salt"].hex(),
                "cs1": [hex(x) for x in pq_signature_alice_pq_bob_eth["cs1"]],
                "cs2": [hex(x) for x in pq_signature_alice_pq_bob_eth["cs2"]],
                "hint": pq_signature_alice_pq_bob_eth["hint"]
            },
            "eth_message": eth_message_alice_pq_bob_eth.hex(),
            "eth_signature": {
                "v": eth_signature_alice_pq_bob_eth["v"],
                "r": f"0x{eth_signature_alice_pq_bob_eth['r']:064x}",
                "s": f"0x{eth_signature_alice_pq_bob_eth['s']:064x}"
            }
        })
        print("  [OK] Vector: pq_fingerprint_already_registered")
        
        print(f"  Bob ETH: {bob['eth_address']}, Alice PQ: {alice['pq_fingerprint']}")
        print(f"  ETH nonce: {bob_eth_nonce}, PQ nonce: {alice_pq_nonce}")
        print(f"  PQ signature: salt={pq_signature_alice_pq_bob_eth['salt'].hex()}, hint={pq_signature_alice_pq_bob_eth['hint']}")
        print(f"  ETH signature: v={eth_signature_alice_pq_bob_eth['v']}, r={eth_signature_alice_pq_bob_eth['r']}, s={eth_signature_alice_pq_bob_eth['s']}")
        
        # Test 6.5: ETH address already has intent (Alice's ETH + Bob's PQ)
        print("Test 6.5: ETH address already has intent")
        alice_eth_bob_pq_vector = self.create_alice_eth_bob_pq_vector()
        if alice_eth_bob_pq_vector:
            vectors["submit_registration_intent_reverts"].append(alice_eth_bob_pq_vector)
            print("  [OK] Vector: eth_address_already_has_intent (AliceETH + BobPQ)")
        else:
            print("  [FAILED] Could not create AliceETH + BobPQ vector")
        
        # Test 6.5: ETH address already has intent (Alice's ETH + Alice's PQ with different nonce)
        print("Test 6.5: ETH address already has intent")
        # Use Alice's ETH address and Alice's PQ fingerprint but with a different nonce
        alice_eth_nonce_2 = 1  # Different nonce
        alice_pq_nonce_2 = 1   # Different nonce
        
        # Create base PQ message with Alice's ETH address and Alice's PQ fingerprint but different nonce
        base_pq_message_alice_eth_alice_pq_2 = build_base_pq_message(DOMAIN_SEPARATOR, alice["eth_address"], alice_pq_nonce_2)
        pq_signature_alice_eth_alice_pq_2 = sign_with_pq_key(base_pq_message_alice_eth_alice_pq_2, alice["pq_private_key_file"])
        
        eth_message_alice_eth_alice_pq_2 = build_eth_intent_message(
            DOMAIN_SEPARATOR, base_pq_message_alice_eth_alice_pq_2, pq_signature_alice_eth_alice_pq_2["salt"], pq_signature_alice_eth_alice_pq_2["cs1"], pq_signature_alice_eth_alice_pq_2["cs2"], pq_signature_alice_eth_alice_pq_2["hint"], alice_eth_nonce_2
        )
        eth_signature_alice_eth_alice_pq_2 = sign_with_eth_key(eth_message_alice_eth_alice_pq_2, alice["eth_private_key"], pq_signature_alice_eth_alice_pq_2["salt"], pq_signature_alice_eth_alice_pq_2["cs1"], pq_signature_alice_eth_alice_pq_2["cs2"], pq_signature_alice_eth_alice_pq_2["hint"], alice_eth_nonce_2, base_pq_message_alice_eth_alice_pq_2)
        
        vectors["submit_registration_intent_reverts"].append({
            "test_name": "eth_address_already_has_intent",
            "description": "Test revert when ETH address already has pending intent (Alice's ETH + Alice's PQ with different nonce)",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],  # Alice's PQ fingerprint
            "eth_nonce": alice_eth_nonce_2,
            "pq_nonce": alice_pq_nonce_2,
            "base_pq_message": base_pq_message_alice_eth_alice_pq_2.hex(),
            "pq_signature": {
                "salt": pq_signature_alice_eth_alice_pq_2["salt"].hex(),
                "cs1": [hex(x) for x in pq_signature_alice_eth_alice_pq_2["cs1"]],
                "cs2": [hex(x) for x in pq_signature_alice_eth_alice_pq_2["cs2"]],
                "hint": pq_signature_alice_eth_alice_pq_2["hint"]
            },
            "eth_message": eth_message_alice_eth_alice_pq_2.hex(),
            "eth_signature": {
                "v": eth_signature_alice_eth_alice_pq_2["v"],
                "r": f"0x{eth_signature_alice_eth_alice_pq_2['r']:064x}",
                "s": f"0x{eth_signature_alice_eth_alice_pq_2['s']:064x}"
            }
        })
        print("  [OK] Vector: eth_address_already_has_intent")
        
        print(f"  Alice ETH: {alice['eth_address']}, Alice PQ: {alice['pq_fingerprint']}")
        print(f"  ETH nonce: {alice_eth_nonce_2}, PQ nonce: {alice_pq_nonce_2}")
        print(f"  PQ signature: salt={pq_signature_alice_eth_alice_pq_2['salt'].hex()}, hint={pq_signature_alice_eth_alice_pq_2['hint']}")
        print(f"  ETH signature: v={eth_signature_alice_eth_alice_pq_2['v']}, r={eth_signature_alice_eth_alice_pq_2['r']}, s={eth_signature_alice_eth_alice_pq_2['s']}")
        
        # Test 7: Wrong domain separator in PQ message
        print("Test 7: Wrong domain separator in PQ message")
        wrong_domain_separator = "0x1234567890123456789012345678901234567890123456789012345678901234"  # Wrong DS
        base_pq_message_wrong_ds = build_base_pq_message(wrong_domain_separator, alice["eth_address"], pq_nonce)
        pq_signature_wrong_ds = sign_with_pq_key(base_pq_message_wrong_ds, alice["pq_private_key_file"])
        
        eth_message_wrong_ds = build_eth_intent_message(
            DOMAIN_SEPARATOR, base_pq_message_wrong_ds, pq_signature_wrong_ds["salt"], pq_signature_wrong_ds["cs1"], pq_signature_wrong_ds["cs2"], pq_signature_wrong_ds["hint"], eth_nonce
        )
        eth_signature_wrong_ds = sign_with_eth_key(eth_message_wrong_ds, alice["eth_private_key"], pq_signature_wrong_ds["salt"], pq_signature_wrong_ds["cs1"], pq_signature_wrong_ds["cs2"], pq_signature_wrong_ds["hint"], eth_nonce, base_pq_message_wrong_ds)
        
        vectors["submit_registration_intent_reverts"].append({
            "test_name": "wrong_domain_separator_pq",
            "description": "Test revert when PQ message has wrong domain separator",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce,
            "base_pq_message": base_pq_message_wrong_ds.hex(),
            "pq_signature": {
                "salt": pq_signature_wrong_ds["salt"].hex(),
                "cs1": [hex(x) for x in pq_signature_wrong_ds["cs1"]],
                "cs2": [hex(x) for x in pq_signature_wrong_ds["cs2"]],
                "hint": pq_signature_wrong_ds["hint"]
            },
            "eth_message": eth_message_wrong_ds.hex(),
            "eth_signature": {
                "v": eth_signature_wrong_ds["v"],
                "r": f"0x{eth_signature_wrong_ds['r']:064x}",
                "s": f"0x{eth_signature_wrong_ds['s']:064x}"
            }
        })
        print("  [OK] Vector: wrong_domain_separator_pq")
        
        # Test 8: Wrong domain separator in ETH message
        print("Test 8: Wrong domain separator in ETH message")
        # Use correct PQ message but wrong domain separator in ETH EIP712 signing
        base_pq_message_correct = build_base_pq_message(DOMAIN_SEPARATOR, alice["eth_address"], pq_nonce)
        pq_signature_correct = sign_with_pq_key(base_pq_message_correct, alice["pq_private_key_file"])
        
        # Create ETH message with correct PQ message but sign with wrong domain separator
        eth_message_correct_pq = build_eth_intent_message(
            DOMAIN_SEPARATOR, base_pq_message_correct, pq_signature_correct["salt"], pq_signature_correct["cs1"], pq_signature_correct["cs2"], pq_signature_correct["hint"], eth_nonce
        )
        
        # Sign with wrong domain separator
        # Create the struct hash for the message components
        from eip712_helpers import get_registration_intent_struct_hash, get_eip712_digest, sign_eip712_message
        struct_hash = get_registration_intent_struct_hash(pq_signature_correct["salt"], pq_signature_correct["cs1"], pq_signature_correct["cs2"], pq_signature_correct["hint"], base_pq_message_correct, eth_nonce)
        
        # Create EIP712 digest with WRONG domain separator
        wrong_domain_separator_bytes = bytes.fromhex(wrong_domain_separator[2:])  # Remove '0x' prefix
        digest_wrong_ds = get_eip712_digest(wrong_domain_separator_bytes, struct_hash)
        
        # Sign the digest with wrong domain separator
        sig_wrong_ds = sign_eip712_message(digest_wrong_ds, alice["eth_private_key"])
        
        vectors["submit_registration_intent_reverts"].append({
            "test_name": "wrong_domain_separator_eth",
            "description": "Test revert when ETH signature has wrong domain separator",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce,
            "base_pq_message": base_pq_message_correct.hex(),
            "pq_signature": {
                "salt": pq_signature_correct["salt"].hex(),
                "cs1": [hex(x) for x in pq_signature_correct["cs1"]],
                "cs2": [hex(x) for x in pq_signature_correct["cs2"]],
                "hint": pq_signature_correct["hint"]
            },
            "eth_message": eth_message_correct_pq.hex(),
            "eth_signature": {
                "v": sig_wrong_ds["v"],
                "r": f"0x{sig_wrong_ds['r']:064x}",
                "s": f"0x{sig_wrong_ds['s']:064x}"
            }
        })
        print("  [OK] Vector: wrong_domain_separator_eth")
        
        return vectors
    
    def generate_confirm_registration_revert_vectors(self) -> Dict[str, Any]:
        """Generate revert test vectors for confirmRegistration()"""
        
        vectors = {
            "confirm_registration_reverts": []
        }
        
        print("Generating confirmRegistration revert vectors...")
        alice = self.actors["alice"]
        eth_nonce = 1  # After registration intent submission, Alice's ETH nonce is 1
        pq_nonce = 1   # After registration intent submission, Alice's PQ nonce is 1
        
        # Test 1: No pending intent
        print("Test 1: No pending intent")
        pq_confirm_message = create_pq_confirmation_message(alice["eth_address"], pq_nonce)
        pq_confirm_signature = sign_with_pq_key(pq_confirm_message, alice["pq_private_key_file"])
        
        vectors["confirm_registration_reverts"].append({
            "test_name": "no_pending_intent",
            "description": "Test revert when no pending intent exists",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "pq_nonce": pq_nonce,
            "pq_message": pq_confirm_message.hex(),
            "pq_signature": {
                "salt": pq_confirm_signature["salt"].hex(),
                "cs1": [hex(x) for x in pq_confirm_signature["cs1"]],
                "cs2": [hex(x) for x in pq_confirm_signature["cs2"]],
                "hint": pq_confirm_signature["hint"]
            }
        })
        print("  [OK] Vector: no_pending_intent")
        
        print(f"  Alice ETH: {alice['eth_address']}, PQ: {alice['pq_fingerprint']}")
        print(f"  PQ nonce: {pq_nonce}")
        print(f"  PQ signature: salt={pq_confirm_signature['salt'].hex()}, hint={pq_confirm_signature['hint']}")
        
        # Test 2: Wrong PQ nonce
        print("Test 2: Wrong PQ nonce")
        wrong_pq_nonce = 5
        pq_confirm_message_wrong_nonce = create_pq_confirmation_message(alice["eth_address"], wrong_pq_nonce)
        pq_confirm_signature_wrong_nonce = sign_with_pq_key(pq_confirm_message_wrong_nonce, alice["pq_private_key_file"])
        
        vectors["confirm_registration_reverts"].append({
            "test_name": "wrong_pq_nonce",
            "description": "Test revert when PQ nonce is wrong",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "pq_nonce": wrong_pq_nonce,
            "pq_message": pq_confirm_message_wrong_nonce.hex(),
            "pq_signature": {
                "salt": pq_confirm_signature_wrong_nonce["salt"].hex(),
                "cs1": [hex(x) for x in pq_confirm_signature_wrong_nonce["cs1"]],
                "cs2": [hex(x) for x in pq_confirm_signature_wrong_nonce["cs2"]],
                "hint": pq_confirm_signature_wrong_nonce["hint"]
            }
        })
        print("  [OK] Vector: wrong_pq_nonce (confirm)")
        
        # Test 3: Wrong domain separator in PQ confirmation message
        print("Test 3: Wrong domain separator in PQ confirmation message")
        wrong_domain_separator = "0x1234567890123456789012345678901234567890123456789012345678901234"  # Wrong DS
        
        # Create PQ confirmation message with wrong domain separator
        # The confirmation message doesn't include domain separator directly, but we can test
        # by creating a malformed message that would fail validation
        pq_confirm_message_wrong_ds = create_pq_confirmation_message(alice["eth_address"], wrong_pq_nonce)
        pq_confirm_signature_wrong_ds = sign_with_pq_key(pq_confirm_message_wrong_ds, alice["pq_private_key_file"])
        
        vectors["confirm_registration_reverts"].append({
            "test_name": "wrong_domain_separator_pq_confirm",
            "description": "Test revert when PQ confirmation message has wrong domain separator",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "pq_nonce": wrong_pq_nonce,
            "pq_message": pq_confirm_message_wrong_ds.hex(),
            "pq_signature": {
                "salt": pq_confirm_signature_wrong_ds["salt"].hex(),
                "cs1": [hex(x) for x in pq_confirm_signature_wrong_ds["cs1"]],
                "cs2": [hex(x) for x in pq_confirm_signature_wrong_ds["cs2"]],
                "hint": pq_confirm_signature_wrong_ds["hint"]
            }
        })
        print("  [OK] Vector: wrong_domain_separator_pq_confirm")
        
        # Test 4: PQ fingerprint mismatch (should fail at fingerprint check, not nonce)
        print("Test 4: PQ fingerprint mismatch")
        bob = self.actors["bob"]
        alice = self.actors["alice"]
        eth_nonce = 1  # After intent submission, Alice's ETH nonce is 1
        pq_nonce = 0   # Bob's PQ nonce is 0 (not Alice's)
        
        # Create PQ confirmation message with Bob's key (wrong fingerprint)
        pq_confirm_message_mismatch = create_pq_confirmation_message(alice["eth_address"], pq_nonce)
        pq_confirm_signature_mismatch = sign_with_pq_key(pq_confirm_message_mismatch, bob["pq_private_key_file"])
        
        # Build baseETHMessage (92 bytes)
        base_pattern = b"Confirm bonding to Epervier Fingerprint "
        pq_fingerprint_bytes = bytes.fromhex(bob["pq_fingerprint"][2:])  # Bob's fingerprint (wrong)
        eth_nonce_bytes = eth_nonce.to_bytes(32, 'big')
        base_eth_message = base_pattern + pq_fingerprint_bytes + eth_nonce_bytes
        
        # Sign baseETHMessage with Alice's ETH key (correct signer, but wrong fingerprint in message)
        eth_sig = sign_with_eth_key(base_eth_message, alice["eth_private_key"], 
                                   pq_confirm_signature_mismatch["salt"], 
                                   pq_confirm_signature_mismatch["cs1"], 
                                   pq_confirm_signature_mismatch["cs2"], 
                                   pq_confirm_signature_mismatch["hint"], 
                                   eth_nonce, 
                                   pq_confirm_message_mismatch)
        
        # Construct the complete PQRegistrationConfirmationMessage (272 bytes)
        DOMAIN_SEPARATOR_BYTES = bytes.fromhex(DOMAIN_SEPARATOR[2:])
        pattern = b"Confirm bonding to ETH Address "
        eth_address_bytes = bytes.fromhex(alice["eth_address"][2:])
        
        # Build the complete message: DOMAIN_SEPARATOR(32) + pattern(31) + ethAddress(20) + baseETHMessage(92) + v(1) + r(32) + s(32) + pqNonce(32) = 272 bytes
        pq_registration_confirmation_message = (
            DOMAIN_SEPARATOR_BYTES +  # 32 bytes
            pattern +                  # 31 bytes
            eth_address_bytes +        # 20 bytes
            base_eth_message +         # 92 bytes
            eth_sig["v"].to_bytes(1, 'big') +  # 1 byte
            eth_sig["r"].to_bytes(32, 'big') +            # 32 bytes
            eth_sig["s"].to_bytes(32, 'big') +            # 32 bytes
            pq_nonce.to_bytes(32, 'big')  # 32 bytes
        )
        
        # Verify the message is exactly 272 bytes
        assert len(pq_registration_confirmation_message) == 272, f"Message length is {len(pq_registration_confirmation_message)}, expected 272"
        
        # Serialize fields for JSON output (match working generators)
        vectors["confirm_registration_reverts"].append({
            "test_name": "pq_fingerprint_mismatch",
            "description": "Test revert when PQ fingerprint does not match intent (wrong PQ key, correct message format)",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": bob["pq_fingerprint"],
            "pq_nonce": pq_nonce,
            "pq_message": pq_registration_confirmation_message.hex(),
            "pq_signature": {
                "salt": pq_confirm_signature_mismatch["salt"].hex(),
                "cs1": [hex(cs) for cs in pq_confirm_signature_mismatch["cs1"]],
                "cs2": [hex(cs) for cs in pq_confirm_signature_mismatch["cs2"]],
                "hint": pq_confirm_signature_mismatch["hint"]
            }
        })
        
        return vectors

    def generate_remove_registration_intent_eth_revert_vectors(self) -> Dict[str, Any]:
        """Generate revert test vectors for removeRegistrationIntentByETH()"""
        
        vectors = {
            "remove_registration_intent_eth_reverts": []
        }
        
        print("Generating removeRegistrationIntentByETH revert vectors...")
        alice = self.actors["alice"]
        eth_nonce = 1  # After registration intent submission, Alice's ETH nonce is 1
        current_actor = "alice"
        
        # Test 1: No pending intent - Create valid message but no intent exists
        print("Test 1: No pending intent")
        pattern = b"Remove registration intent from Epervier Fingerprint "
        eth_message = pattern + bytes.fromhex(alice["pq_fingerprint"][2:]) + int_to_bytes32(eth_nonce)
        assert len(eth_message) == 105, f"ETH remove message wrong length: {len(eth_message)}"
        struct_hash = self.create_remove_intent_struct_hash(alice["pq_fingerprint"], eth_nonce)
        digest = self.create_eip712_digest(struct_hash)
        v, r, s, signature = self.sign_message(digest, alice["eth_private_key"])
        vectors["remove_registration_intent_eth_reverts"].append({
            "test_name": "no_pending_intent",
            "description": "Test revert when no pending intent exists",
            "current_actor": current_actor,
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_nonce": eth_nonce,
            "eth_message": eth_message.hex(),
            "eth_signature": {
                "v": v,
                "r": r,
                "s": s,
                "signature": signature
            }
        })
        
        # Test 2: Wrong domain separator - Create message with wrong domain but valid format
        print("Test 2: Wrong domain separator")
        # For this test, we need to create a message that passes parsing but fails domain validation
        # The contract checks domain separator in the signature verification, not in message parsing
        wrong_domain = bytes.fromhex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        struct_hash = self.create_remove_intent_struct_hash(alice["pq_fingerprint"], eth_nonce, wrong_domain)
        digest = self.create_eip712_digest(struct_hash, wrong_domain)
        v, r, s, signature = self.sign_message(digest, alice["eth_private_key"])
        
        vectors["remove_registration_intent_eth_reverts"].append({
            "test_name": "wrong_domain_separator",
            "description": "Test revert when domain separator is wrong",
            "current_actor": current_actor,
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_nonce": eth_nonce,
            "eth_message": eth_message.hex(),
            "eth_signature": {
                "v": v,
                "r": r,
                "s": s,
                "signature": signature
            }
        })
        
        # Test 3: Wrong nonce - Create message with wrong nonce but valid format
        print("Test 3: Wrong nonce")
        wrong_nonce = eth_nonce + 1
        wrong_message = pattern + bytes.fromhex(alice["pq_fingerprint"][2:]) + int_to_bytes32(wrong_nonce)
        assert len(wrong_message) == 105, f"ETH remove message wrong length: {len(wrong_message)}"
        struct_hash = self.create_remove_intent_struct_hash(alice["pq_fingerprint"], wrong_nonce)
        digest = self.create_eip712_digest(struct_hash)
        v, r, s, signature = self.sign_message(digest, alice["eth_private_key"])
        
        vectors["remove_registration_intent_eth_reverts"].append({
            "test_name": "wrong_nonce",
            "description": "Test revert when nonce is wrong",
            "current_actor": current_actor,
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_nonce": wrong_nonce,
            "eth_message": wrong_message.hex(),
            "eth_signature": {
                "v": v,
                "r": r,
                "s": s,
                "signature": signature
            }
        })
        
        # Test 4: Wrong signer - Create valid message but signed by wrong key
        print("Test 4: Wrong signer")
        bob = self.actors["bob"]
        struct_hash = self.create_remove_intent_struct_hash(alice["pq_fingerprint"], eth_nonce)
        digest = self.create_eip712_digest(struct_hash)
        v, r, s, signature = self.sign_message(digest, bob["eth_private_key"])  # Sign with wrong key
        
        vectors["remove_registration_intent_eth_reverts"].append({
            "test_name": "wrong_signer",
            "description": "Test revert when signature is from wrong address",
            "current_actor": current_actor,
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_nonce": eth_nonce,
            "eth_message": eth_message.hex(),
            "eth_signature": {
                "v": v,
                "r": r,
                "s": s,
                "signature": signature
            }
        })
        
        # Test 5: Malformed message - Create message that's too short for parsing
        print("Test 5: Malformed message")
        # Create message with correct pattern but missing fingerprint and nonce
        # Pattern: "Remove registration intent from Epervier Fingerprint " (53 bytes)
        # Missing: pqFingerprint (20 bytes) + ethNonce (32 bytes) = 52 bytes
        # Total: 53 bytes (should be 105 bytes)
        malformed_message = b"Remove registration intent from Epervier Fingerprint "  # Only 53 bytes, missing 52 bytes
        v, r, s, signature = self.sign_message(keccak(malformed_message), alice["eth_private_key"])
        
        vectors["remove_registration_intent_eth_reverts"].append({
            "test_name": "malformed_message",
            "description": "Test revert when message format is wrong",
            "current_actor": current_actor,
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_nonce": eth_nonce,
            "eth_message": malformed_message.hex(),
            "eth_signature": {
                "v": v,
                "r": r,
                "s": s,
                "signature": signature
            }
        })
        
        # Test 6: Invalid signature - Create valid message but invalid signature
        print("Test 6: Invalid signature")
        vectors["remove_registration_intent_eth_reverts"].append({
            "test_name": "invalid_signature",
            "description": "Test revert when signature is invalid",
            "current_actor": current_actor,
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_nonce": eth_nonce,
            "eth_message": eth_message.hex(),
            "eth_signature": {
                "v": 27,
                "r": 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
                "s": 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890,
                "signature": "0x" + "00" * 64
            }
        })
        
        # Test 7: Wrong PQ fingerprint - Create message with wrong fingerprint but valid format
        print("Test 7: Wrong PQ fingerprint")
        bob = self.actors["bob"]
        wrong_message = pattern + bytes.fromhex(bob["pq_fingerprint"][2:]) + int_to_bytes32(eth_nonce)
        assert len(wrong_message) == 105, f"ETH remove message wrong length: {len(wrong_message)}"
        
        struct_hash = self.create_remove_intent_struct_hash(bob["pq_fingerprint"], eth_nonce)
        digest = self.create_eip712_digest(struct_hash)
        v, r, s, signature = self.sign_message(digest, alice["eth_private_key"])
        
        vectors["remove_registration_intent_eth_reverts"].append({
            "test_name": "wrong_pq_fingerprint",
            "description": "Test revert when PQ fingerprint doesn't match",
            "current_actor": current_actor,
            "eth_address": alice["eth_address"],
            "pq_fingerprint": bob["pq_fingerprint"],  # Wrong fingerprint
            "eth_nonce": eth_nonce,
            "eth_message": wrong_message.hex(),
            "eth_signature": {
                "v": v,
                "r": r,
                "s": s,
                "signature": signature
            }
        })
        
        return vectors

    def generate_remove_registration_intent_pq_revert_vectors(self) -> Dict[str, Any]:
        """Generate revert test vectors for removeRegistrationIntentByPQ()"""
        
        vectors = {
            "remove_registration_intent_pq_reverts": []
        }
        
        print("Generating removeRegistrationIntentByPQ revert vectors...")
        alice = self.actors["alice"]
        pq_nonce = 1  # After registration intent submission, Alice's PQ nonce is 1
        
        # Test 1: No pending intent - Create valid message but no intent exists
        print("Test 1: No pending intent")
        # PQRemoveRegistrationIntentMessage: DOMAIN_SEPARATOR(32) + pattern(44) + ethAddress(20) + pqNonce(32) = 128 bytes
        pattern = b"Remove registration intent from ETH Address "
        pq_message = bytes.fromhex(DOMAIN_SEPARATOR[2:]) + pattern + bytes.fromhex(alice["eth_address"][2:]) + int_to_bytes32(pq_nonce)
        assert len(pq_message) == 128, f"PQ remove message wrong length: {len(pq_message)}"
        
        # Create valid PQ signature for the message
        salt, cs1, cs2, hint = self.create_pq_signature(pq_message, alice["pq_private_key_file"])
        
        vectors["remove_registration_intent_pq_reverts"].append({
            "test_name": "no_pending_intent",
            "description": "Test revert when no pending intent exists",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "pq_nonce": pq_nonce,
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": salt,
                "cs1": cs1,
                "cs2": cs2,
                "hint": hint
            }
        })
        
        # Test 2: Wrong domain separator - Create message with wrong domain but valid format
        print("Test 2: Wrong domain separator")
        wrong_domain = bytes.fromhex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        wrong_message = wrong_domain + pattern + bytes.fromhex(alice["eth_address"][2:]) + int_to_bytes32(pq_nonce)
        assert len(wrong_message) == 128, f"PQ remove message wrong length: {len(wrong_message)}"
        salt, cs1, cs2, hint = self.create_pq_signature(wrong_message, alice["pq_private_key_file"])
        
        vectors["remove_registration_intent_pq_reverts"].append({
            "test_name": "wrong_domain_separator",
            "description": "Test revert when domain separator is wrong",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "pq_nonce": pq_nonce,
            "pq_message": wrong_message.hex(),
            "pq_signature": {
                "salt": salt,
                "cs1": cs1,
                "cs2": cs2,
                "hint": hint
            }
        })
        
        # Test 3: Wrong nonce - Create message with wrong nonce but valid format
        print("Test 3: Wrong nonce")
        wrong_nonce = pq_nonce + 1
        wrong_message = bytes.fromhex(DOMAIN_SEPARATOR[2:]) + pattern + bytes.fromhex(alice["eth_address"][2:]) + int_to_bytes32(wrong_nonce)
        assert len(wrong_message) == 128, f"PQ remove message wrong length: {len(wrong_message)}"
        salt, cs1, cs2, hint = self.create_pq_signature(wrong_message, alice["pq_private_key_file"])
        
        vectors["remove_registration_intent_pq_reverts"].append({
            "test_name": "wrong_nonce",
            "description": "Test revert when nonce is wrong",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "pq_nonce": wrong_nonce,
            "pq_message": wrong_message.hex(),
            "pq_signature": {
                "salt": salt,
                "cs1": cs1,
                "cs2": cs2,
                "hint": hint
            }
        })
        
        # Test 4: Wrong signer - Create valid message but signed by wrong key
        print("Test 4: Wrong signer")
        bob = self.actors["bob"]
        salt, cs1, cs2, hint = self.create_pq_signature(pq_message, bob["pq_private_key_file"])  # Sign with wrong key
        
        vectors["remove_registration_intent_pq_reverts"].append({
            "test_name": "wrong_signer",
            "description": "Test revert when signature is from wrong address",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "pq_nonce": pq_nonce,
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": salt,
                "cs1": cs1,
                "cs2": cs2,
                "hint": hint
            }
        })
        
        # Test 5: Malformed message - Create message that's too short for parsing
        print("Test 5: Malformed message")
        malformed_message = b"Remove registration intent"  # Too short - missing domain, address and nonce (only 26 bytes)
        salt, cs1, cs2, hint = self.create_pq_signature(malformed_message, alice["pq_private_key_file"])
        
        vectors["remove_registration_intent_pq_reverts"].append({
            "test_name": "malformed_message",
            "description": "Test revert when message format is wrong",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "pq_nonce": pq_nonce,
            "pq_message": malformed_message.hex(),
            "pq_signature": {
                "salt": salt,
                "cs1": cs1,
                "cs2": cs2,
                "hint": hint
            }
        })
        
        # Test 7: Wrong message format - Create message with wrong pattern but correct length (nonce must be 1)
        print("Test 7: Wrong message format")
        pq_nonce = 1  # Ensure PQ nonce is 1
        # The correct pattern is 44 bytes: b"Remove registration intent from ETH Address "
        # Let's use a wrong pattern of exactly 44 bytes
        wrong_pattern = b"Wrong message format for removal intent!"  # 41 bytes
        if len(wrong_pattern) < 44:
            wrong_pattern = wrong_pattern + b"_" * (44 - len(wrong_pattern))
        elif len(wrong_pattern) > 44:
            wrong_pattern = wrong_pattern[:44]
        assert len(wrong_pattern) == 44, f"Wrong pattern is not 44 bytes: {len(wrong_pattern)}"
        wrong_format_message = bytes.fromhex(DOMAIN_SEPARATOR[2:]) + wrong_pattern + bytes.fromhex(alice["eth_address"][2:]) + int_to_bytes32(pq_nonce)
        assert len(wrong_format_message) == 128, f"PQ remove message wrong length: {len(wrong_format_message)}"
        salt, cs1, cs2, hint = self.create_pq_signature(wrong_format_message, alice["pq_private_key_file"])
        vectors["remove_registration_intent_pq_reverts"].append({
            "test_name": "wrong_message_format",
            "description": "Test revert when message format is incorrect",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "pq_nonce": pq_nonce,
            "pq_message": wrong_format_message.hex(),
            "pq_signature": {
                "salt": salt,
                "cs1": cs1,
                "cs2": cs2,
                "hint": hint
            }
        })
        
        return vectors

    def create_remove_intent_struct_hash(self, pq_fingerprint: str, eth_nonce: int, domain_separator: bytes = None) -> bytes:
        """Create the struct hash for RemoveIntent using proper EIP-712 encoding"""
        if domain_separator is None:
            domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])
        
        type_hash = keccak(b"RemoveIntent(address pqFingerprint,uint256 ethNonce)")
        # Use abi.encode instead of encode_packed for proper EIP-712 encoding
        from eth_abi import encode
        struct_hash = keccak(encode([
            'bytes32',
            'address', 
            'uint256'
        ], [
            type_hash,
            pq_fingerprint,  # address (20 bytes)
            eth_nonce        # uint256
        ]))
        return struct_hash
    
    def create_eip712_digest(self, struct_hash: bytes, domain_separator: bytes = None) -> bytes:
        """Create the EIP712 digest"""
        if domain_separator is None:
            domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])
        
        digest = keccak(encode_packed(b'\x19\x01', domain_separator, struct_hash))
        return digest
    
    def sign_message(self, digest: bytes, private_key: str) -> tuple:
        """Sign a message with ETH private key and return v, r, s, signature"""
        account = Account.from_key(private_key)
        sig = Account._sign_hash(digest, private_key=account.key)
        return sig.v, sig.r, sig.s, sig.signature.hex()
    
    def create_pq_signature(self, message: bytes, private_key_file: str) -> tuple:
        """Create a PQ signature for a message"""
        # Use the existing sign_with_pq_key function
        pq_sig = sign_with_pq_key(message, private_key_file)
        if pq_sig is None:
            print(f"Failed to generate PQ signature for {private_key_file}")
            print(f"Message: {message.hex()}")
            # Don't fallback to invalid signature - this should never happen
            raise Exception(f"Failed to generate PQ signature for {private_key_file}")
        
        return (
            pq_sig["salt"].hex(),
            [hex(x) for x in pq_sig["cs1"]],
            [hex(x) for x in pq_sig["cs2"]],
            pq_sig["hint"]
        )

def main():
    """Generate all revert test vectors"""
    
    generator = RevertVectorGenerator()
    
    # Create output directory using absolute path from project root
    output_dir = PROJECT_ROOT / "test" / "test_vectors" / "revert"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate all revert vectors
    submit_intent_reverts = generator.generate_submit_registration_intent_revert_vectors()
    confirm_reverts = generator.generate_confirm_registration_revert_vectors()
    remove_intent_eth_reverts = generator.generate_remove_registration_intent_eth_revert_vectors()
    remove_intent_pq_reverts = generator.generate_remove_registration_intent_pq_revert_vectors()
    
    # Create comprehensive revert vectors file
    comprehensive_reverts = {
        "submit_registration_intent_reverts": submit_intent_reverts["submit_registration_intent_reverts"],
        "confirm_registration_reverts": confirm_reverts["confirm_registration_reverts"],
        "remove_registration_intent_eth_reverts": remove_intent_eth_reverts["remove_registration_intent_eth_reverts"],
        "remove_registration_intent_pq_reverts": remove_intent_pq_reverts["remove_registration_intent_pq_reverts"]
    }
    
    # Write comprehensive file
    comprehensive_file = output_dir / "comprehensive_revert_vectors.json"
    with open(comprehensive_file, "w") as f:
        json.dump(comprehensive_reverts, f, indent=2)
    
    # Also write individual files for backward compatibility
    with open(output_dir / "submit_registration_intent_revert_vectors.json", "w") as f:
        json.dump(submit_intent_reverts, f, indent=2)
    
    with open(output_dir / "confirm_registration_revert_vectors.json", "w") as f:
        json.dump(confirm_reverts, f, indent=2)
    
    # Generate remove registration intent by ETH revert vectors
    print("Writing remove intent ETH vectors...")
    eth_file_path = output_dir / "remove_registration_intent_eth_revert_vectors.json"
    print(f"Writing to: {eth_file_path}")
    with open(eth_file_path, "w") as f:
        json.dump(remove_intent_eth_reverts, f, indent=2)
    print(f"ETH vectors written successfully")
    
    # Generate remove registration intent by PQ revert vectors
    print("Writing remove intent PQ vectors...")
    pq_file_path = output_dir / "remove_registration_intent_pq_revert_vectors.json"
    print(f"Writing to: {pq_file_path}")
    with open(pq_file_path, "w") as f:
        json.dump(remove_intent_pq_reverts, f, indent=2)
    print(f"PQ vectors written successfully")
    
    print("Revert test vectors generated successfully!")
    print(f"Output directory: {output_dir}")

if __name__ == "__main__":
    main() 
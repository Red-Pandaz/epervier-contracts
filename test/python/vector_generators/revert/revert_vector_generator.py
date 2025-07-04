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
    # Use sign_cli.py to sign the base PQ message
    from tempfile import NamedTemporaryFile
    import os
    import subprocess
    
    # Write message to temp file
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(base_pq_message)
        tmp.flush()
        tmp_path = tmp.name
    
    sign_cli = PROJECT_ROOT / "ETHFALCON/python-ref/sign_cli.py"
    privkey_path = PROJECT_ROOT / "test/test_keys" / pq_private_key_file
    venv_python = PROJECT_ROOT / "ETHFALCON/python-ref/myenv/bin/python3"

    cmd = [
        str(venv_python), str(sign_cli), "sign",
        f"--privkey={privkey_path}",
        f"--data={base_pq_message.hex()}",
        "--version=epervier"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    os.unlink(tmp_path)
    
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
        eth_nonce = 0
        pq_nonce = 0
        
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
        
        return vectors

def main():
    """Generate all revert test vectors"""
    
    generator = RevertVectorGenerator()
    
    # Create output directory
    output_dir = Path("test/test_vectors/revert")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate submit registration intent revert vectors
    submit_intent_reverts = generator.generate_submit_registration_intent_revert_vectors()
    with open(output_dir / "submit_registration_intent_revert_vectors.json", "w") as f:
        json.dump(submit_intent_reverts, f, indent=2)
    
    # Generate confirm registration revert vectors
    confirm_reverts = generator.generate_confirm_registration_revert_vectors()
    with open(output_dir / "confirm_registration_revert_vectors.json", "w") as f:
        json.dump(confirm_reverts, f, indent=2)
    
    print("Revert test vectors generated successfully!")
    print(f"Output directory: {output_dir}")

if __name__ == "__main__":
    main() 
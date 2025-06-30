#!/usr/bin/env python3
"""
Advanced Test Scenario Generator

This generator creates vectors specifically for the advanced test scenario:
"ETH Registration - PQ Removes - ETH Retries - PQ Confirms"

The test requires vectors with specific nonce values:
- registration_intent_nonce2: ETH nonce 2, PQ nonce 2
- registration_confirmation_nonce3: ETH nonce 2, PQ nonce 3
"""

import json
import os
import subprocess
from pathlib import Path
from typing import Dict, Any, List
from eth_account import Account
from eth_hash.auto import keccak
from tempfile import NamedTemporaryFile
from eth_utils import keccak

# Project root
PROJECT_ROOT = Path(__file__).resolve().parents[4]  # epervier-registry

# Domain separator (same as in the contract)
DOMAIN_SEPARATOR = bytes.fromhex("5f5d847b41fe04c02ecf9746150300028bfc195e7981ae8fe39fe8b7a745650f")

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')

def load_actors_config() -> Dict[str, Any]:
    """Load actor configuration from the main config file"""
    config_file = PROJECT_ROOT / "test" / "test_keys" / "actors_config.json"
    with open(config_file, 'r') as f:
        return json.load(f)

def abi_encode_packed(*args) -> bytes:
    """Simple ABI encode packed implementation"""
    result = b""
    for arg in args:
        if isinstance(arg, str):
            result += arg.encode('utf-8')
        elif isinstance(arg, bytes):
            result += arg
        elif isinstance(arg, int):
            result += arg.to_bytes(32, 'big')
        else:
            result += arg
    return result

def generate_eth_signature(message: bytes, private_key: str) -> Dict[str, Any]:
    """Generate ETH signature for a message"""
    account = Account.from_key(private_key)
    message_hash = keccak(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode() + message)
    signature = Account._sign_hash(message_hash, private_key=account.key)
    return {
        "v": signature.v,
        "r": signature.r,
        "s": signature.s
    }

def generate_epervier_signature(message: bytes, actor_config: dict) -> Dict[str, Any]:
    """Generate Epervier signature using the CLI"""
    sign_cli = str(PROJECT_ROOT / "ETHFALCON" / "python-ref" / "sign_cli.py")
    privkey_path = str(PROJECT_ROOT / "test" / "test_keys" / actor_config["pq_private_key_file"])
    venv_python = str(PROJECT_ROOT / "ETHFALCON" / "python-ref" / "myenv" / "bin" / "python3")
    cmd = [
        venv_python, sign_cli, "sign",
        f"--privkey={privkey_path}",
        f"--data={message.hex()}",
        "--version=epervier"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to generate Epervier signature: {result.stderr}")
    lines = result.stdout.splitlines()
    signature_data = {}
    for line in lines:
        if line.startswith("salt:"):
            signature_data["salt"] = line.split()[1]
        elif line.startswith("hint:"):
            signature_data["hint"] = int(line.split()[1])
        elif line.startswith("cs1:"):
            signature_data["cs1"] = [int(x, 16) for x in line.split()[1:]]
        elif line.startswith("cs2:"):
            signature_data["cs2"] = [int(x, 16) for x in line.split()[1:]]
    return signature_data

def pack_uint256_array(arr: List[int]) -> bytes:
    """Pack array of uint256 values into bytes"""
    result = b""
    for val in arr:
        result += val.to_bytes(32, 'big')
    return result

def create_base_pq_registration_intent_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create base PQ registration intent message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair ETH Address ",
        eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

def create_eth_registration_intent_message(base_pq_message: bytes, salt: str, cs1: List[int], cs2: List[int], hint: int, eth_nonce: int) -> bytes:
    """Create ETH registration intent message"""
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair Epervier Key",
        base_pq_message,
        bytes.fromhex(salt[2:]) if isinstance(salt, str) else salt,
        pack_uint256_array(cs1),
        pack_uint256_array(cs2),
        hint.to_bytes(32, 'big'),
        eth_nonce.to_bytes(32, 'big')
    )

def create_base_eth_registration_confirmation_message(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Create base ETH registration confirmation message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Confirm bonding to Epervier Fingerprint ",
        pq_fingerprint_bytes,
        eth_nonce.to_bytes(32, 'big')
    )

def create_pq_registration_confirmation_message(eth_address: str, base_eth_message: bytes, v: int, r: int, s: int, pq_nonce: int) -> bytes:
    """Create PQ registration confirmation message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Confirm bonding to ETH Address ",
        eth_address_bytes,
        base_eth_message,
        v.to_bytes(1, 'big'),
        r.to_bytes(32, 'big'),
        s.to_bytes(32, 'big'),
        pq_nonce.to_bytes(32, 'big')
    )

def build_base_pq_message(domain_separator, eth_address, pq_nonce):
    # DOMAIN_SEPARATOR (32) + "Intent to pair ETH Address " (27) + ethAddress (20) + pqNonce (32) = 111 bytes
    # This matches BasePQRegistrationIntentMessage in schema
    pattern = b"Intent to pair ETH Address "
    return domain_separator + pattern + bytes.fromhex(eth_address[2:]) + int_to_bytes32(pq_nonce)

def build_base_eth_confirmation_message(domain_separator, pq_fingerprint, eth_nonce):
    # DOMAIN_SEPARATOR (32) + "Confirm bonding to Epervier Fingerprint " (40) + pqFingerprint (20) + ethNonce (32) = 124 bytes
    # This matches BaseETHRegistrationConfirmationMessage in schema
    pattern = b"Confirm bonding to Epervier Fingerprint "
    return domain_separator + pattern + bytes.fromhex(pq_fingerprint[2:]) + int_to_bytes32(eth_nonce)

def build_pq_confirmation_message(domain_separator, eth_address, base_eth_message, v, r, s, pq_nonce):
    # DOMAIN_SEPARATOR (32) + "Confirm bonding to ETH Address " (31) + ethAddress (20) + baseETHMessage (124) + v (1) + r (32) + s (32) + pqNonce (32) = 304 bytes
    # This matches PQRegistrationConfirmationMessage in schema
    pattern = b"Confirm bonding to ETH Address "
    return (
        domain_separator + pattern + bytes.fromhex(eth_address[2:]) + base_eth_message +
        v.to_bytes(1, 'big') + r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + int_to_bytes32(pq_nonce)
    )

def build_eth_intent_message(domain_separator, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    # DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
    # This matches ETHRegistrationIntentMessage in schema
    pattern = b"Intent to pair Epervier Key"
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    return (
        domain_separator + pattern + base_pq_message + salt +
        pack_uint256_array(cs1) + pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') + int_to_bytes32(eth_nonce)
    )

def sign_with_pq_key(base_pq_message, pq_private_key_file):
    # Use sign_cli.py to sign the base PQ message
    # Returns dict with salt, cs1, cs2, hint
    # Write message to temp file
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(base_pq_message)
        tmp.flush()
        tmp_path = tmp.name
    # Find the project root (assuming this script is at test/python/vector_generators/)
    project_root = Path(__file__).resolve().parents[3]  # epervier-registry

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

def sign_with_eth_key(eth_intent_message, eth_private_key):
    # Use Ethereum's personal_sign format
    eth_message_length = len(eth_intent_message)
    eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + eth_intent_message
    eth_message_hash = keccak(eth_signed_message)
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(eth_message_hash, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}

def generate_test_2_vectors():
    """Generate vectors for Test 2: PQ Registration → ETH Removes → PQ Retries → ETH Confirms"""
    print("Starting Test 2 vector generation...")
    
    # Load actors config
    actors_config = load_actors_config()
    bob = actors_config["actors"]["bob"]
    
    print(f"Processing Bob: {bob['eth_address']}")
    
    # Step 3: PQ creates new registration intent (nonce 1) after ETH removal
    print("Step 3: Creating new registration intent with PQ nonce 1...")
    
    # Build base PQ message for nonce 1
    base_pq_message = build_base_pq_message(DOMAIN_SEPARATOR, bob["eth_address"], 1)
    print(f"Base PQ message length: {len(base_pq_message)} bytes")
    
    # PQ sign the base message
    pq_sig = sign_with_pq_key(base_pq_message, bob["pq_private_key_file"])
    if pq_sig is None:
        print("Failed to generate PQ signature!")
        return None
    
    # Build ETH intent message with embedded PQ signature
    eth_intent_message = build_eth_intent_message(
        DOMAIN_SEPARATOR, base_pq_message, pq_sig["salt"], 
        pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], 2
    )
    print(f"ETH intent message length: {len(eth_intent_message)} bytes")
    
    # ETH sign the intent message
    eth_sig = sign_with_eth_key(eth_intent_message, bob["eth_private_key"])
    
    # Create registration intent vector
    registration_intent_vector = {
        "actor": "bob",
        "eth_address": bob["eth_address"],
        "pq_fingerprint": bob["pq_fingerprint"],
        "base_pq_message": base_pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"].hex(),
            "cs1": [hex(cs) for cs in pq_sig["cs1"]],
            "cs2": [hex(cs) for cs in pq_sig["cs2"]],
            "hint": pq_sig["hint"],
            "raw_signature": ""
        },
        "eth_message": eth_intent_message.hex(),
        "eth_signature": eth_sig,
        "eth_nonce": 2,
        "pq_nonce": 1
    }
    
    # Step 4: ETH confirms registration (nonce 2)
    print("Step 4: Creating registration confirmation with ETH nonce 2...")
    
    # Build base ETH confirmation message
    base_eth_message = build_base_eth_confirmation_message(
        DOMAIN_SEPARATOR, bob["pq_fingerprint"], 3
    )
    print(f"Base ETH confirmation message length: {len(base_eth_message)} bytes")
    
    # ETH sign the confirmation message
    eth_confirmation_sig = sign_with_eth_key(base_eth_message, bob["eth_private_key"])
    
    # Build PQ confirmation message with embedded ETH signature
    pq_confirmation_message = build_pq_confirmation_message(
        DOMAIN_SEPARATOR, bob["eth_address"], base_eth_message,
        eth_confirmation_sig["v"], eth_confirmation_sig["r"], eth_confirmation_sig["s"], 2
    )
    print(f"PQ confirmation message length: {len(pq_confirmation_message)} bytes")
    
    # PQ sign the confirmation message
    pq_confirmation_sig = sign_with_pq_key(pq_confirmation_message, bob["pq_private_key_file"])
    if pq_confirmation_sig is None:
        print("Failed to generate PQ confirmation signature!")
        return None
    
    # Create registration confirmation vector
    registration_confirmation_vector = {
        "actor": "bob",
        "eth_address": bob["eth_address"],
        "pq_fingerprint": bob["pq_fingerprint"],
        "base_eth_message": base_eth_message.hex(),
        "eth_signature": eth_confirmation_sig,
        "pq_message": pq_confirmation_message.hex(),
        "pq_signature": {
            "salt": pq_confirmation_sig["salt"].hex(),
            "cs1": [hex(cs) for cs in pq_confirmation_sig["cs1"]],
            "cs2": [hex(cs) for cs in pq_confirmation_sig["cs2"]],
            "hint": pq_confirmation_sig["hint"],
            "raw_signature": ""
        },
        "eth_nonce": 3,
        "pq_nonce": 2
    }
    
    # Create Test 2 output structure
    test2_output = {
        "registration_intent_nonce2_pq1": [registration_intent_vector],
        "registration_confirmation_nonce2_pq2": [registration_confirmation_vector]
    }
    
    print("Test 2 vector generation complete!")
    return test2_output

def generate_advanced_test_vectors():
    """Generate vectors for the advanced test scenario"""
    print("Starting advanced test vector generation...")
    
    # Load actors config
    actors_config = load_actors_config()
    alice = actors_config["actors"]["alice"]
    
    print(f"Processing Alice: {alice['eth_address']}")
    
    # Step 1: ETH creates registration intent (nonce 2)
    print("Step 1: Creating registration intent with nonce 2...")
    
    # Build base PQ message for nonce 2
    base_pq_message = build_base_pq_message(DOMAIN_SEPARATOR, alice["eth_address"], 2)
    print(f"Base PQ message length: {len(base_pq_message)} bytes")
    
    # PQ sign the base message
    pq_sig = sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])
    if pq_sig is None:
        print("Failed to generate PQ signature!")
        return None
    
    # Build ETH intent message with embedded PQ signature
    eth_intent_message = build_eth_intent_message(
        DOMAIN_SEPARATOR, base_pq_message, pq_sig["salt"], 
        pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], 1
    )
    print(f"ETH intent message length: {len(eth_intent_message)} bytes")
    
    # ETH sign the intent message
    eth_sig = sign_with_eth_key(eth_intent_message, alice["eth_private_key"])
    
    # Create registration intent vector
    registration_intent_vector = {
        "actor": "alice",
        "eth_address": alice["eth_address"],
        "pq_fingerprint": alice["pq_fingerprint"],
        "base_pq_message": base_pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"].hex(),
            "cs1": [hex(cs) for cs in pq_sig["cs1"]],
            "cs2": [hex(cs) for cs in pq_sig["cs2"]],
            "hint": pq_sig["hint"],
            "raw_signature": ""
        },
        "eth_message": eth_intent_message.hex(),
        "eth_signature": eth_sig,
        "eth_nonce": 2,
        "pq_nonce": 1
    }
    
    # Step 2: PQ creates registration confirmation (nonce 3)
    print("Step 2: Creating registration confirmation with nonce 3...")
    
    # Build base ETH confirmation message
    base_eth_message = build_base_eth_confirmation_message(
        DOMAIN_SEPARATOR, alice["pq_fingerprint"], 2
    )
    print(f"Base ETH confirmation message length: {len(base_eth_message)} bytes")
    
    # ETH sign the confirmation message
    eth_confirmation_sig = sign_with_eth_key(base_eth_message, alice["eth_private_key"])
    
    # Build PQ confirmation message with embedded ETH signature
    pq_confirmation_message = build_pq_confirmation_message(
        DOMAIN_SEPARATOR, alice["eth_address"], base_eth_message,
        eth_confirmation_sig["v"], eth_confirmation_sig["r"], eth_confirmation_sig["s"], 3
    )
    print(f"PQ confirmation message length: {len(pq_confirmation_message)} bytes")
    
    # PQ sign the confirmation message
    pq_confirmation_sig = sign_with_pq_key(pq_confirmation_message, alice["pq_private_key_file"])
    if pq_confirmation_sig is None:
        print("Failed to generate PQ confirmation signature!")
        return None
    
    # Create registration confirmation vector
    registration_confirmation_vector = {
        "actor": "alice",
        "eth_address": alice["eth_address"],
        "pq_fingerprint": alice["pq_fingerprint"],
        "base_eth_message": base_eth_message.hex(),
        "eth_signature": eth_confirmation_sig,
        "pq_message": pq_confirmation_message.hex(),
        "pq_signature": {
            "salt": pq_confirmation_sig["salt"].hex(),
            "cs1": [hex(cs) for cs in pq_confirmation_sig["cs1"]],
            "cs2": [hex(cs) for cs in pq_confirmation_sig["cs2"]],
            "hint": pq_confirmation_sig["hint"],
            "raw_signature": ""
        },
        "eth_nonce": 2,
        "pq_nonce": 1
    }
    
    # Create final output structure
    output = {
        "registration_intent_nonce2": [registration_intent_vector],
        "registration_confirmation_nonce3": [registration_confirmation_vector]
    }
    
    # Write to file
    output_path = PROJECT_ROOT / "test/test_vectors/advanced/correct_advanced_vectors.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"Advanced test vectors written to {output_path}")
    print("Vector generation complete!")
    
    return output

def create_base_eth_change_eth_address_message(pq_fingerprint, new_eth_address, eth_nonce):
    """Create base ETH message for change ETH address intent"""
    # Remove 0x prefix and convert to bytes
    fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])
    new_addr_bytes = bytes.fromhex(new_eth_address[2:])
    
    # Create message: domain_separator + intent_text + fingerprint + " to " + new_address + eth_nonce
    intent_text = "Intent to change ETH Address and bond with Epervier Fingerprint "
    message = DOMAIN_SEPARATOR + intent_text.encode() + fingerprint_bytes + " to ".encode() + new_addr_bytes
    
    # Add ETH nonce
    message += eth_nonce.to_bytes(32, 'big')
    
    return message

def create_nested_change_eth_address_intent_message(old_eth_address, new_eth_address, pq_fingerprint, base_eth_message, eth_signature, pq_nonce):
    """Create nested message for change ETH address intent"""
    old_addr_bytes = bytes.fromhex(old_eth_address[2:])
    new_addr_bytes = bytes.fromhex(new_eth_address[2:])
    fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])
    intent_text = "Intent to change bound ETH Address from "
    
    # Create message: domain_separator + intent_text + old_address + " to " + new_address + base_eth_message + eth_signature + pq_nonce
    message = DOMAIN_SEPARATOR + intent_text.encode() + old_addr_bytes + " to ".encode() + new_addr_bytes + base_eth_message
    
    # Add ETH signature components
    message += eth_signature['v'].to_bytes(1, 'big')
    message += eth_signature['r'].to_bytes(32, 'big')
    message += eth_signature['s'].to_bytes(32, 'big')
    
    # Add PQ nonce
    message += pq_nonce.to_bytes(32, 'big')
    
    return message

def generate_change_eth_address_intent_vectors():
    """Generate change ETH address intent vectors for tests 4 and 5"""
    vectors = []
    
    # Load actor configuration
    config_file = PROJECT_ROOT / "test" / "test_keys" / "actors_config.json"
    with open(config_file, 'r') as f:
        actors_config = json.load(f)
    
    alice_config = actors_config["actors"]["alice"]
    charlie_config = actors_config["actors"]["charlie"]
    
    # Test 4: PQ nonce 4, ETH nonce 0
    base_eth_message_4 = create_base_eth_change_eth_address_message(
        alice_config["pq_fingerprint"], 
        charlie_config["eth_address"], 
        0
    )
    eth_signature_4 = generate_eth_signature(base_eth_message_4, alice_config["eth_private_key"])
    
    nested_message_4 = create_nested_change_eth_address_intent_message(
        alice_config["eth_address"],
        charlie_config["eth_address"], 
        alice_config["pq_fingerprint"],
        base_eth_message_4,
        eth_signature_4,
        4
    )
    pq_signature_4 = generate_epervier_signature(nested_message_4, alice_config)
    
    # Test 5: PQ nonce 3, ETH nonce 0
    base_eth_message_5 = create_base_eth_change_eth_address_message(
        alice_config["pq_fingerprint"], 
        charlie_config["eth_address"], 
        0
    )
    eth_signature_5 = generate_eth_signature(base_eth_message_5, alice_config["eth_private_key"])
    
    nested_message_5 = create_nested_change_eth_address_intent_message(
        alice_config["eth_address"],
        charlie_config["eth_address"], 
        alice_config["pq_fingerprint"],
        base_eth_message_5,
        eth_signature_5,
        3
    )
    pq_signature_5 = generate_epervier_signature(nested_message_5, alice_config)
    
    # Test 4 vector
    vectors.append({
        "current_actor": "alice",
        "new_actor": "charlie",
        "old_eth_address": alice_config["eth_address"],
        "new_eth_address": charlie_config["eth_address"],
        "pq_fingerprint": alice_config["pq_fingerprint"],
        "pq_message": nested_message_4.hex(),
        "pq_signature": {
            "salt": pq_signature_4["salt"],
            "hint": pq_signature_4["hint"],
            "cs1": pq_signature_4["cs1"],
            "cs2": pq_signature_4["cs2"]
        },
        "eth_message": base_eth_message_4.hex(),
        "eth_signature": {
            "v": eth_signature_4["v"],
            "r": eth_signature_4["r"],
            "s": eth_signature_4["s"]
        },
        "pq_nonce": 4,
        "eth_nonce": 0
    })
    
    # Test 5 vector
    vectors.append({
        "current_actor": "alice",
        "new_actor": "charlie",
        "old_eth_address": alice_config["eth_address"],
        "new_eth_address": charlie_config["eth_address"],
        "pq_fingerprint": alice_config["pq_fingerprint"],
        "pq_message": nested_message_5.hex(),
        "pq_signature": {
            "salt": pq_signature_5["salt"],
            "hint": pq_signature_5["hint"],
            "cs1": pq_signature_5["cs1"],
            "cs2": pq_signature_5["cs2"]
        },
        "eth_message": base_eth_message_5.hex(),
        "eth_signature": {
            "v": eth_signature_5["v"],
            "r": eth_signature_5["r"],
            "s": eth_signature_5["s"]
        },
        "pq_nonce": 3,
        "eth_nonce": 0
    })
    
    return {"change_eth_address_intent": vectors}

def generate_change_eth_address_confirmation_vectors():
    """Generate change ETH address confirmation vectors for tests 4 and 5"""
    vectors = []
    
    # Load actor configuration
    config_file = PROJECT_ROOT / "test" / "test_keys" / "actors_config.json"
    with open(config_file, 'r') as f:
        actors_config = json.load(f)
    
    alice_config = actors_config["actors"]["alice"]
    charlie_config = actors_config["actors"]["charlie"]
    
    # Test 4: PQ nonce 5 (after intent step)
    base_pq_message_4 = create_base_pq_change_eth_address_confirmation_message(
        alice_config["eth_address"], 
        charlie_config["eth_address"], 
        5
    )
    pq_signature_4 = generate_epervier_signature(base_pq_message_4, alice_config)
    
    # Test 5: PQ nonce 4 (after intent step)
    base_pq_message_5 = create_base_pq_change_eth_address_confirmation_message(
        alice_config["eth_address"], 
        charlie_config["eth_address"], 
        4
    )
    pq_signature_5 = generate_epervier_signature(base_pq_message_5, alice_config)
    
    # Create nested messages and signatures
    nested_message_4 = create_nested_change_eth_address_confirmation_message(
        alice_config["eth_address"],
        charlie_config["eth_address"], 
        alice_config["pq_fingerprint"],
        base_pq_message_4,
        pq_signature_4,
        5
    )
    eth_signature_4 = generate_eth_signature(nested_message_4, charlie_config["eth_private_key"])
    
    nested_message_5 = create_nested_change_eth_address_confirmation_message(
        alice_config["eth_address"],
        charlie_config["eth_address"], 
        alice_config["pq_fingerprint"],
        base_pq_message_5,
        pq_signature_5,
        4
    )
    eth_signature_5 = generate_eth_signature(nested_message_5, charlie_config["eth_private_key"])
    
    # Test 4 vector
    vectors.append({
        "current_actor": "alice",
        "new_actor": "charlie",
        "old_eth_address": alice_config["eth_address"],
        "new_eth_address": charlie_config["eth_address"],
        "pq_fingerprint": alice_config["pq_fingerprint"],
        "base_pq_message": base_pq_message_4.hex(),
        "pq_signature": pq_signature_4,
        "eth_message": nested_message_4.hex(),
        "eth_signature": eth_signature_4,
        "pq_nonce": 5,
        "eth_nonce": 1
    })
    
    # Test 5 vector
    vectors.append({
        "current_actor": "alice",
        "new_actor": "charlie",
        "old_eth_address": alice_config["eth_address"],
        "new_eth_address": charlie_config["eth_address"],
        "pq_fingerprint": alice_config["pq_fingerprint"],
        "base_pq_message": base_pq_message_5.hex(),
        "pq_signature": pq_signature_5,
        "eth_message": nested_message_5.hex(),
        "eth_signature": eth_signature_5,
        "pq_nonce": 4,
        "eth_nonce": 1
    })
    
    return {"change_eth_address_confirmation": vectors}

def create_base_eth_message(domain_separator, pq_fingerprint, new_eth_address, eth_nonce):
    """Create BaseETHChangeETHAddressIntentMessage (172 bytes)"""
    # DOMAIN_SEPARATOR (32) + pattern (64) + pqFingerprint (20) + pattern2 (4) + newEthAddress (20) + ethNonce (32) = 172 bytes
    pattern = b"Intent to change ETH Address and bond with Epervier Fingerprint "
    pattern2 = b" to "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        pattern2 +
        bytes.fromhex(new_eth_address[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def create_base_pq_message(domain_separator, old_eth_address, new_eth_address, base_eth_message, v, r, s, pq_nonce):
    """Create PQChangeETHAddressIntentMessage (376 bytes)"""
    # DOMAIN_SEPARATOR (32) + pattern (40) + oldEthAddress (20) + pattern2 (4) + newEthAddress (20) + baseETHMessage (172) + v (1) + r (32) + s (32) + pqNonce (32) = 376 bytes
    pattern = b"Intent to change bound ETH Address from "
    pattern2 = b" to "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(old_eth_address[2:]) +  # Remove "0x" prefix
        pattern2 +
        bytes.fromhex(new_eth_address[2:]) +  # Remove "0x" prefix
        base_eth_message +
        v.to_bytes(1, 'big') +
        r.to_bytes(32, 'big') +
        s.to_bytes(32, 'big') +
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_base_pq_confirmation_message(domain_separator, old_eth_address, new_eth_address, pq_nonce):
    """Create BasePQChangeETHAddressConfirmMessage (173 bytes)"""
    # DOMAIN_SEPARATOR (32) + pattern (65) + oldEthAddress (20) + pattern2 (4) + newEthAddress (20) + pqNonce (32) = 173 bytes
    pattern = b"Confirm changing bound ETH Address for Epervier Fingerprint from "
    pattern2 = b" to "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(old_eth_address[2:]) +  # Remove "0x" prefix
        pattern2 +
        bytes.fromhex(new_eth_address[2:]) +  # Remove "0x" prefix
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_eth_confirmation_message(domain_separator, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    """Create ETHChangeETHAddressConfirmationMessage (2411 bytes)"""
    # DOMAIN_SEPARATOR (32) + pattern (52) + pqFingerprint (20) + basePQMessage (173) + salt (40) + cs1 (1024) + cs2 (1024) + hint (32) + ethNonce (32) = 2411 bytes
    pattern = b"Confirm change ETH Address for Epervier Fingerprint "
    
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        base_pq_message +
        bytes.fromhex(salt[2:]) if isinstance(salt, str) else salt +
        pack_uint256_array(cs1) +
        pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') +
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def generate_bob_nonce1_vector():
    """Generate registration intent vector for Bob with nonce 1 (for Step 3 of Test 2)"""
    # Load actor configuration
    config_file = PROJECT_ROOT / "test" / "test_keys" / "actors_config.json"
    with open(config_file, 'r') as f:
        actors_config = json.load(f)
    
    bob_config = actors_config["actors"]["bob"]
    
    # Generate base PQ message with nonce 1
    base_pq_message = create_base_pq_registration_intent_message(bob_config["eth_address"], 1)
    
    # Generate PQ signature
    pq_signature = generate_epervier_signature(base_pq_message, bob_config)
    
    # Create ETH registration intent message (nested message)
    eth_intent_message = create_eth_registration_intent_message(
        base_pq_message,
        pq_signature["salt"],
        pq_signature["cs1"],
        pq_signature["cs2"],
        pq_signature["hint"],
        2  # ETH nonce should be 2 after Step 2
    )
    
    # Generate ETH signature for the nested message
    eth_signature = generate_eth_signature(eth_intent_message, bob_config["eth_private_key"])
    
    # Create vector structure
    vector = {
        "actor": "bob",
        "eth_address": bob_config["eth_address"],
        "pq_fingerprint": bob_config["pq_fingerprint"],
        "base_pq_message": base_pq_message.hex(),
        "pq_signature": {
            "salt": pq_signature["salt"],
            "cs1": [hex(cs) for cs in pq_signature["cs1"]],
            "cs2": [hex(cs) for cs in pq_signature["cs2"]],
            "hint": pq_signature["hint"]
        },
        "pq_message": eth_intent_message.hex(),  # Full nested message
        "eth_message": eth_intent_message.hex(),    # Same as pq_message for registration intent
        "eth_signature": {
            "v": eth_signature["v"],
            "r": eth_signature["r"],
            "s": eth_signature["s"]
        },
        "eth_nonce": 2,
        "pq_nonce": 1
    }
    
    return vector

def create_base_pq_change_eth_address_message(old_eth_address, new_eth_address, pq_nonce):
    """Create base PQ message for change ETH address intent"""
    # Remove 0x prefix and convert to bytes
    old_addr_bytes = bytes.fromhex(old_eth_address[2:])
    new_addr_bytes = bytes.fromhex(new_eth_address[2:])
    
    # Create message: domain_separator + intent_text + old_address + new_address + pq_nonce
    intent_text = "Intent to change bound ETH Address from "
    message = DOMAIN_SEPARATOR + intent_text.encode() + old_addr_bytes + " to ".encode() + new_addr_bytes
    
    # Add PQ nonce
    message += pq_nonce.to_bytes(32, 'big')
    
    return message

def _cs_to_bytes(cs):
    if isinstance(cs, str) and cs.startswith("0x"):
        return bytes.fromhex(cs[2:])
    elif isinstance(cs, int):
        return cs.to_bytes(32, 'big')
    else:
        raise ValueError(f"Unexpected cs value: {cs}")

def create_nested_change_eth_address_message(old_eth_address, new_eth_address, pq_fingerprint, base_pq_message, pq_signature, pq_nonce):
    """Create nested message for change ETH address intent"""
    old_addr_bytes = bytes.fromhex(old_eth_address[2:])
    new_addr_bytes = bytes.fromhex(new_eth_address[2:])
    fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])
    intent_text = "Intent to change ETH Address and bond with Epervier Fingerprint "
    salt_bytes = bytes.fromhex(pq_signature["salt"])
    hint_bytes = pq_signature["hint"].to_bytes(32, 'big')
    cs1_bytes = b''.join([_cs_to_bytes(cs) for cs in pq_signature["cs1"]])
    cs2_bytes = b''.join([_cs_to_bytes(cs) for cs in pq_signature["cs2"]])
    message = (DOMAIN_SEPARATOR + intent_text.encode() + old_addr_bytes + 
               " to ".encode() + new_addr_bytes + fingerprint_bytes + 
               base_pq_message + salt_bytes + hint_bytes + cs1_bytes + cs2_bytes + 
               pq_nonce.to_bytes(32, 'big'))
    return message

def create_base_pq_change_eth_address_confirmation_message(old_eth_address, new_eth_address, pq_nonce):
    """Create base PQ message for change ETH address confirmation"""
    # Remove 0x prefix and convert to bytes
    old_addr_bytes = bytes.fromhex(old_eth_address[2:])
    new_addr_bytes = bytes.fromhex(new_eth_address[2:])
    
    # Create message: domain_separator + confirm_text + old_address + new_address + pq_nonce
    confirm_text = "Confirm changing bound ETH Address for Epervier Fingerprint from "
    message = DOMAIN_SEPARATOR + confirm_text.encode() + old_addr_bytes + " to ".encode() + new_addr_bytes + pq_nonce.to_bytes(32, 'big')
    
    return message

def create_nested_change_eth_address_confirmation_message(old_eth_address, new_eth_address, pq_fingerprint, base_pq_message, pq_signature, pq_nonce):
    """Create nested message for change ETH address confirmation"""
    old_addr_bytes = bytes.fromhex(old_eth_address[2:])
    new_addr_bytes = bytes.fromhex(new_eth_address[2:])
    fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])
    eth_nonce = 1  # Charlie's nonce for confirmation
    salt_bytes = bytes.fromhex(pq_signature["salt"])
    hint_bytes = pq_signature["hint"].to_bytes(32, 'big')
    cs1_bytes = b''.join([_cs_to_bytes(cs) for cs in pq_signature["cs1"]])
    cs2_bytes = b''.join([_cs_to_bytes(cs) for cs in pq_signature["cs2"]])
    message = (base_pq_message + salt_bytes + hint_bytes + cs1_bytes + cs2_bytes + 
               eth_nonce.to_bytes(32, 'big'))
    return message

def main():
    """Main function to generate advanced test vectors"""
    print("Generating advanced test vectors...")
    
    # Generate Test 1 vectors (ETH Registration → PQ Removes → ETH Retries → PQ Confirms)
    test1_vectors = generate_advanced_test_vectors()
    
    # Generate Test 2 vectors (PQ Registration → ETH Removes → PQ Retries → ETH Confirms)
    test2_vectors = generate_test_2_vectors()
    
    # Generate advanced test vectors
    advanced_vectors = generate_advanced_test_vectors()
    
    # Generate change ETH address vectors
    change_intent_vectors = generate_change_eth_address_intent_vectors()
    change_confirmation_vectors = generate_change_eth_address_confirmation_vectors()
    
    # Generate Bob nonce 1 vector for Step 3 of Test 2
    bob_nonce1_vector = generate_bob_nonce1_vector()
    
    # Save all vectors
    vectors_dir = PROJECT_ROOT / "test" / "test_vectors"
    vectors_dir.mkdir(exist_ok=True)
    
    # Save Test 1 vectors
    with open(vectors_dir / "test1_eth_retry_vectors.json", 'w') as f:
        json.dump(test1_vectors, f, indent=2)
    
    # Save Test 2 vectors
    with open(vectors_dir / "test2_pq_retry_vectors.json", 'w') as f:
        json.dump(test2_vectors, f, indent=2)
    
    # Save advanced vectors
    advanced_dir = vectors_dir / "advanced"
    advanced_dir.mkdir(exist_ok=True)
    with open(advanced_dir / "correct_advanced_vectors.json", 'w') as f:
        json.dump(advanced_vectors, f, indent=2)
    
    # Save change ETH address vectors
    with open(vectors_dir / "change_eth_address_intent_vectors.json", 'w') as f:
        json.dump(change_intent_vectors, f, indent=2)
    
    with open(vectors_dir / "change_eth_address_confirmation_vectors.json", 'w') as f:
        json.dump(change_confirmation_vectors, f, indent=2)
    
    # Save Bob nonce 1 vector
    with open(vectors_dir / "bob_nonce1_vector.json", 'w') as f:
        json.dump({"bob_nonce1_vector": [bob_nonce1_vector]}, f, indent=2)
    
    print("All vectors generated successfully!")

if __name__ == "__main__":
    main() 
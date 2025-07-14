#!/usr/bin/env python3
"""
Generate confirmation revert test vectors with real signatures.
"""

import json
import subprocess
import sys
import os
from pathlib import Path
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
from eth_hash.auto import keccak
from eth_utils import to_checksum_address
from eth_abi import encode

# Get the script directory for proper path resolution
SCRIPT_DIR = Path(__file__).parent.absolute()

# Import the necessary modules for signature parsing
sys.path.append(str(SCRIPT_DIR.parent.parent.parent.parent / "ETHFALCON/python-ref"))
sys.path.append(str(SCRIPT_DIR.parent.parent))
from common import falcon_compact, q
from encoding import decompress
from polyntt.poly import Poly

# Import domain separator from config
from eip712_config import DOMAIN_SEPARATOR

# Foundry default private keys
ETH_PRIVATE_KEYS = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118e8d7e3bdfa4b9b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
]

# Constants from the CLI code
HEAD_LEN = 1
SALT_LEN = 40

def abi_encode_packed(*args):
    """Concatenate arguments without padding (like Solidity's abi.encodePacked)"""
    result = b''
    for arg in args:
        if isinstance(arg, str):
            result += arg.encode('utf-8')
        elif isinstance(arg, bytes):
            result += arg
        elif isinstance(arg, int):
            # Convert to 32-byte big-endian
            result += arg.to_bytes(32, 'big')
        elif isinstance(arg, list):
            # For arrays, convert each element to 32-byte big-endian
            for item in arg:
                result += item.to_bytes(32, 'big')
        else:
            raise ValueError(f"Unsupported type: {type(arg)}")
    return result

def pack_uint256_array(arr):
    """Pack uint256 array into bytes without length prefix"""
    result = b''
    for item in arr:
        result += item.to_bytes(32, 'big')
    return result

def parse_signature_file(sig_file_path):
    """Parse the signature file to extract salt, cs1, cs2, hint"""
    try:
        with open(sig_file_path, 'r') as f:
            sig_hex = f.read().strip()
        
        # Convert hex to bytes
        sig_bytes = bytes.fromhex(sig_hex)
        
        # Extract salt (first 40 bytes after header)
        salt = sig_bytes[HEAD_LEN:HEAD_LEN + SALT_LEN]
        
        # Extract the encoded signature part (everything after salt, except last 512*3 bytes)
        enc_s = sig_bytes[HEAD_LEN + SALT_LEN:-512*3]
        
        # Decompress the signature components
        s = decompress(enc_s, 666*2 - HEAD_LEN - SALT_LEN, 512*2)
        mid = len(s)//2
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
            "salt": salt.hex(),
            "cs1": s1_compact,
            "cs2": s2_compact,
            "hint": hint,
            "raw_signature": sig_hex
        }
        
    except Exception as e:
        print(f"Error parsing signature file: {e}")
        return {
            "salt": "0x" + "00" * 40,
            "cs1": [0] * 32,
            "cs2": [0] * 32,
            "hint": 123,
            "raw_signature": ""
        }

def create_base_eth_message(pq_fingerprint, eth_nonce):
    """
    Create base ETH message for registration confirmation
    Format: "Confirm binding to Epervier Fingerprint " + pqFingerprint + ethNonce
    This is signed by the ETH Address (no domain separator in content)
    """
    base_eth_pattern = "Confirm binding to Epervier Fingerprint "
    message = (
        base_eth_pattern.encode() +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def generate_epervier_signature(message, pq_key_index):
    """Generate Epervier signature using the Python CLI - matching working generator"""
    try:
        # Convert message to hex
        message_hex = message.hex() if isinstance(message, bytes) else message.encode().hex()
        
        # Use the correct path to sign_cli.py
        SIGN_CLI_PATH = Path(__file__).parent.parent.parent.parent.parent / "ETHFALCON/python-ref/sign_cli.py"
        
        # Call the Python CLI to sign the message with virtual environment activated
        cmd = [
            "bash", "-c",
            f"cd {SIGN_CLI_PATH.parent} && source myenv/bin/activate && python3 sign_cli.py sign --version epervier --privkey ../../test/test_keys/private_key_{pq_key_index + 1}.pem --data {message_hex}"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(SCRIPT_DIR))
        
        if result.returncode != 0:
            print(f"Warning: Epervier signing failed for key {pq_key_index}: {result.stderr}")
            return None
        
        # Parse the signature components from stdout (matching working generator)
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
            print(f"Failed to parse signature components for key {pq_key_index}")
            return None
        
        return {
            "salt": signature_data["salt"].hex(),
            "cs1": [hex(x) for x in signature_data["cs1"]],
            "cs2": [hex(x) for x in signature_data["cs2"]],
            "hint": signature_data["hint"]
        }
        
    except Exception as e:
        print(f"Error generating Epervier signature: {e}")
        return None

def generate_eip712_signature(pq_fingerprint, eth_nonce, eth_priv_key, domain_separator):
    """Generate EIP-712 signature for ETH confirmation message"""
    from eth_account import Account
    from eth_utils import keccak, to_checksum_address
    from eip712_config import REGISTRATION_CONFIRMATION_TYPE_HASH
    
    # Use the same approach as the working generators
    # Convert pqFingerprint string to hex string with 0x prefix
    pq_fingerprint_hex = pq_fingerprint if pq_fingerprint.startswith('0x') else "0x" + pq_fingerprint
    
    # Use the helper function from eip712_helpers (same as working generators)
    sys.path.append(str(SCRIPT_DIR.parent.parent))
    from eip712_helpers import get_registration_confirmation_struct_hash, get_eip712_digest
    
    # Generate struct hash using the helper function
    struct_hash = get_registration_confirmation_struct_hash(pq_fingerprint_hex, eth_nonce)
    
    # Generate EIP-712 digest
    domain_separator_bytes = bytes.fromhex(domain_separator[2:])  # Remove '0x' prefix
    digest = get_eip712_digest(domain_separator_bytes, struct_hash)
    
    # Sign the digest
    account = Account.from_key(eth_priv_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    
    return sig

def generate_confirm_revert_vectors():
    """Generate confirmation revert test vectors with real signatures"""
    
    # Output file path (correct location for tests)
    output_file = SCRIPT_DIR.parent.parent.parent / "test_vectors/revert/confirm_registration_revert_vectors.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    print("Generating confirmation revert test vectors with real signatures...")
    
    # Convert DOMAIN_SEPARATOR from hex string to bytes
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    
    # Use the first key bind for all tests
    eth_priv_key = ETH_PRIVATE_KEYS[0]
    account = Account.from_key(eth_priv_key)
    eth_address = account.address
    eth_address_bytes = bytes.fromhex(eth_address[2:])
    
    # Use a fixed PQ fingerprint for consistency
    pq_fingerprint = "0x7b317f4d231cbc63de7c6c690ef4ba9c653437fb"
    
    # Start with the existing working vectors
    vectors = []
    
    # Index 0: no_pending_intent - generate real signature
    print("Generating no_pending_intent test...")
    # Create BaseETHRegistrationConfirmationMessage exactly as per schema (92 bytes)
    eth_confirm_message = create_base_eth_message(pq_fingerprint, 1)
    
    eth_sig = generate_eip712_signature(pq_fingerprint, 1, eth_priv_key, DOMAIN_SEPARATOR)
    # Create PQRegistrationConfirmationMessage exactly as per schema (272 bytes)
    pattern = "Confirm binding to ETH Address "
    no_intent_message = (
        domain_separator_bytes +                       # 32 bytes
        pattern.encode() +                             # 31 bytes
        eth_address_bytes +                           # 20 bytes
        eth_confirm_message +                         # 92 bytes
        eth_sig.v.to_bytes(1, 'big') +               # 1 byte (v)
        eth_sig.r.to_bytes(32, 'big') +              # 32 bytes (r)
        eth_sig.s.to_bytes(32, 'big') +              # 32 bytes (s)
        (1).to_bytes(32, 'big')                      # 32 bytes
    )  # Total: 272 bytes exactly
    
    no_intent_sig = generate_epervier_signature(no_intent_message, 0)
    if not no_intent_sig:
        print("Failed to generate signature for no_pending_intent test")
        return
    
    vectors.append({
        "test_name": "no_pending_intent",
        "description": "Test revert when no pending intent exists",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_nonce": 1,
        "pq_message": "0x" + no_intent_message.hex(),
        "pq_signature": {
            "salt": no_intent_sig["salt"],
            "cs1": no_intent_sig["cs1"],
            "cs2": no_intent_sig["cs2"],
            "hint": no_intent_sig["hint"]
        }
    })
    
    # Index 1: wrong_pq_nonce - generate real signature
    print("Generating wrong_pq_nonce test...")
    # Create BaseETHRegistrationConfirmationMessage exactly as per schema (92 bytes)
    eth_confirm_message = create_base_eth_message(pq_fingerprint, 1)
    
    eth_sig = generate_eip712_signature(pq_fingerprint, 1, eth_priv_key, DOMAIN_SEPARATOR)
    # Create PQRegistrationConfirmationMessage with wrong PQ nonce
    pattern = "Confirm binding to ETH Address "
    wrong_nonce_message = (
        domain_separator_bytes +                       # 32 bytes
        pattern.encode() +                             # 31 bytes
        eth_address_bytes +                           # 20 bytes
        eth_confirm_message +                         # 92 bytes
        eth_sig.v.to_bytes(1, 'big') +               # 1 byte (v)
        eth_sig.r.to_bytes(32, 'big') +              # 32 bytes (r)
        eth_sig.s.to_bytes(32, 'big') +              # 32 bytes (s)
        (5).to_bytes(32, 'big')                      # 32 bytes (wrong nonce)
    )  # Total: 272 bytes exactly
    
    wrong_nonce_sig = generate_epervier_signature(wrong_nonce_message, 0)
    if not wrong_nonce_sig:
        print("Failed to generate signature for wrong_pq_nonce test")
        return
    
    vectors.append({
        "test_name": "wrong_pq_nonce",
        "description": "Test revert when PQ nonce is wrong",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_nonce": 5,
        "pq_message": "0x" + wrong_nonce_message.hex(),
        "pq_signature": {
            "salt": wrong_nonce_sig["salt"],
            "cs1": wrong_nonce_sig["cs1"],
            "cs2": wrong_nonce_sig["cs2"],
            "hint": wrong_nonce_sig["hint"]
        }
    })
    
    # Test 2: Wrong domain separator (index 2)
    print("Generating wrong domain separator test...")
    wrong_domain = bytes.fromhex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
    # Create BaseETHRegistrationConfirmationMessage exactly as per schema (92 bytes)
    eth_confirm_message = create_base_eth_message(pq_fingerprint, 1)
    
    eth_sig = generate_eip712_signature(pq_fingerprint, 1, eth_priv_key, DOMAIN_SEPARATOR)
    # Create PQRegistrationConfirmationMessage with wrong domain separator
    pattern = "Confirm binding to ETH Address "
    pq_message = (
        wrong_domain +                                 # 32 bytes (wrong domain)
        pattern.encode() +                             # 31 bytes
        eth_address_bytes +                           # 20 bytes
        eth_confirm_message +                         # 92 bytes
        eth_sig.v.to_bytes(1, 'big') +               # 1 byte (v)
        eth_sig.r.to_bytes(32, 'big') +              # 32 bytes (r)
        eth_sig.s.to_bytes(32, 'big') +              # 32 bytes (s)
        (1).to_bytes(32, 'big')                      # 32 bytes
    )  # Total: 272 bytes exactly
    
    pq_sig = generate_epervier_signature(pq_message, 0)
    if not pq_sig:
        print("Failed to generate signature for wrong domain separator test")
        return
    
    vectors.append({
        "test_name": "wrong_domain_separator",
        "description": "Test revert when PQ confirmation message has wrong domain separator",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_nonce": 1,
        "pq_message": "0x" + pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"],
            "cs1": pq_sig["cs1"],
            "cs2": pq_sig["cs2"],
            "hint": pq_sig["hint"]
        }
    })
    
    # Test 3: Wrong message format (index 3)
    print("Generating wrong message format test...")
    # Create BaseETHRegistrationConfirmationMessage exactly as per schema (92 bytes)
    eth_confirm_message = create_base_eth_message(pq_fingerprint, 1)
    
    eth_sig = generate_eip712_signature(pq_fingerprint, 1, eth_priv_key, DOMAIN_SEPARATOR)
    # Create PQRegistrationConfirmationMessage with wrong format
    pattern = "wrong message format for confirmation"
    pq_message = (
        domain_separator_bytes +                       # 32 bytes
        pattern.encode() +                             # 31 bytes (wrong format)
        eth_address_bytes +                           # 20 bytes
        eth_confirm_message +                         # 92 bytes
        eth_sig.v.to_bytes(1, 'big') +               # 1 byte (v)
        eth_sig.r.to_bytes(32, 'big') +              # 32 bytes (r)
        eth_sig.s.to_bytes(32, 'big') +              # 32 bytes (s)
        (1).to_bytes(32, 'big')                      # 32 bytes
    )  # Total: 272 bytes exactly
    
    pq_sig = generate_epervier_signature(pq_message, 0)
    if not pq_sig:
        print("Failed to generate signature for wrong message format test")
        return
    
    vectors.append({
        "test_name": "wrong_message_format",
        "description": "Test revert when PQ confirmation message has wrong format",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_nonce": 1,
        "pq_message": "0x" + pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"],
            "cs1": pq_sig["cs1"],
            "cs2": pq_sig["cs2"],
            "hint": pq_sig["hint"]
        }
    })
    
    # Test 4: Invalid ETH signature (corrupted signature components) (index 4)
    print("Generating invalid ETH signature test...")
    # Create BaseETHRegistrationConfirmationMessage exactly as per schema (92 bytes)
    eth_confirm_message = create_base_eth_message(pq_fingerprint, 1)
    
    eth_sig = generate_eip712_signature(pq_fingerprint, 1, eth_priv_key, DOMAIN_SEPARATOR)
    # Create PQRegistrationConfirmationMessage with corrupted ETH signature
    pattern = "Confirm binding to ETH Address "
    pq_message = (
        domain_separator_bytes +                       # 32 bytes
        pattern.encode() +                             # 31 bytes
        eth_address_bytes +                           # 20 bytes
        eth_confirm_message +                         # 92 bytes
        bytes([eth_sig.v + 1]) +                      # 1 byte (corrupted v)
        eth_sig.r.to_bytes(32, 'big') +              # 32 bytes (r)
        eth_sig.s.to_bytes(32, 'big') +              # 32 bytes (s)
        (1).to_bytes(32, 'big')                      # 32 bytes
    )  # Total: 272 bytes exactly
    
    pq_sig = generate_epervier_signature(pq_message, 0)
    if not pq_sig:
        print("Failed to generate signature for invalid ETH signature test")
        return
    
    vectors.append({
        "test_name": "invalid_eth_signature",
        "description": "Test revert when ETH signature in PQ message is invalid",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_nonce": 1,
        "pq_message": "0x" + pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"],
            "cs1": pq_sig["cs1"],
            "cs2": pq_sig["cs2"],
            "hint": pq_sig["hint"]
        }
    })
    
    # Test 5: Wrong ETH signer (index 5)
    print("Generating wrong ETH signer test...")
    # Create BaseETHRegistrationConfirmationMessage exactly as per schema (92 bytes)
    eth_confirm_message = create_base_eth_message(pq_fingerprint, 1)
    
    # Use Bob's ETH key to sign (recovering Bob's address)
    bob_eth_priv_key = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"  # Bob's key
    eth_sig = generate_eip712_signature(pq_fingerprint, 1, bob_eth_priv_key, DOMAIN_SEPARATOR)
    
    # Create PQRegistrationConfirmationMessage with wrong ETH signer
    pattern = "Confirm binding to ETH Address "
    pq_message = (
        domain_separator_bytes +                       # 32 bytes
        pattern.encode() +                             # 31 bytes
        eth_address_bytes +                           # 20 bytes (Alice's address)
        eth_confirm_message +                         # 92 bytes
        eth_sig.v.to_bytes(1, 'big') +               # 1 byte (v) - signed by Bob
        eth_sig.r.to_bytes(32, 'big') +              # 32 bytes (r) - signed by Bob
        eth_sig.s.to_bytes(32, 'big') +              # 32 bytes (s) - signed by Bob
        (1).to_bytes(32, 'big')                      # 32 bytes
    )  # Total: 272 bytes exactly
    
    pq_sig = generate_epervier_signature(pq_message, 0)
    if not pq_sig:
        print("Failed to generate signature for wrong ETH signer test")
        return
    
    vectors.append({
        "test_name": "wrong_eth_signer",
        "description": "Test revert when ETH signature is signed by wrong ETH key",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_nonce": 1,
        "pq_message": "0x" + pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"],
            "cs1": pq_sig["cs1"],
            "cs2": pq_sig["cs2"],
            "hint": pq_sig["hint"]
        }
    })
    
    # Test 6: Wrong PQ signer (valid message signed by wrong PQ key) (index 6)
    print("Generating wrong PQ signer test...")
    # Create BaseETHRegistrationConfirmationMessage exactly as per schema (92 bytes)
    eth_confirm_message = create_base_eth_message(pq_fingerprint, 1)
    
    eth_sig = generate_eip712_signature(pq_fingerprint, 1, eth_priv_key, DOMAIN_SEPARATOR)
    # Create PQRegistrationConfirmationMessage with Alice's data
    pattern = "Confirm binding to ETH Address "
    pq_message = (
        domain_separator_bytes +                       # 32 bytes
        pattern.encode() +                             # 31 bytes
        eth_address_bytes +                           # 20 bytes (Alice's address)
        eth_confirm_message +                         # 92 bytes (Alice's fingerprint)
        eth_sig.v.to_bytes(1, 'big') +               # 1 byte (v)
        eth_sig.r.to_bytes(32, 'big') +              # 32 bytes (r)
        eth_sig.s.to_bytes(32, 'big') +              # 32 bytes (s)
        (1).to_bytes(32, 'big')                      # 32 bytes
    )  # Total: 272 bytes exactly
    
    # But sign with Bob's PQ key instead of Alice's
    pq_sig = generate_epervier_signature(pq_message, 1)  # Use Bob's key (index 1)
    if not pq_sig:
        print("Failed to generate signature for wrong PQ signer test")
        return
    
    vectors.append({
        "test_name": "wrong_pq_signer",
        "description": "Test revert when PQ message is signed by wrong PQ key",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_nonce": 1,
        "pq_message": "0x" + pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"],
            "cs1": pq_sig["cs1"],
            "cs2": pq_sig["cs2"],
            "hint": pq_sig["hint"]
        }
    })
    
    # Test 7: Wrong ETH nonce (index 7)
    print("Generating wrong ETH nonce test...")
    # Create BaseETHRegistrationConfirmationMessage with wrong nonce
    eth_confirm_message = create_base_eth_message(pq_fingerprint, 5)
    
    eth_sig = generate_eip712_signature(pq_fingerprint, 5, eth_priv_key, DOMAIN_SEPARATOR)
    pattern = "Confirm binding to ETH Address "
    pq_message = (
        domain_separator_bytes +                       # 32 bytes
        pattern.encode() +                             # 31 bytes
        eth_address_bytes +                           # 20 bytes
        eth_confirm_message +                         # 92 bytes
        eth_sig.v.to_bytes(1, 'big') +               # 1 byte (v)
        eth_sig.r.to_bytes(32, 'big') +              # 32 bytes (r)
        eth_sig.s.to_bytes(32, 'big') +              # 32 bytes (s)
        (1).to_bytes(32, 'big')                      # 32 bytes
    )  # Total: 272 bytes exactly
    
    pq_sig = generate_epervier_signature(pq_message, 0)
    if not pq_sig:
        print("Failed to generate signature for wrong ETH nonce test")
        return
    
    vectors.append({
        "test_name": "wrong_eth_nonce",
        "description": "Test revert when ETH nonce in PQ message is wrong",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_nonce": 1,
        "pq_message": "0x" + pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"],
            "cs1": pq_sig["cs1"],
            "cs2": pq_sig["cs2"],
            "hint": pq_sig["hint"]
        }
    })
    
    # Test 8: ETH address mismatch (index 8)
    print("Generating ETH address mismatch test...")
    # Create BaseETHRegistrationConfirmationMessage with correct data
    eth_confirm_message = create_base_eth_message(pq_fingerprint, 1)
    
    # Use Bob's ETH key to sign (recovering Bob's address)
    bob_eth_priv_key = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"  # Bob's key
    eth_sig = generate_eip712_signature(pq_fingerprint, 1, bob_eth_priv_key, DOMAIN_SEPARATOR)
    
    # Create message with Alice's address but Bob's signature
    # This should cause ETH address mismatch: message contains Alice's address, signature recovers Bob's address
    pattern = "Confirm binding to ETH Address "
    pq_message = (
        domain_separator_bytes +                       # 32 bytes
        pattern.encode() +                             # 31 bytes
        eth_address_bytes +                           # 20 bytes (Alice's address in message)
        eth_confirm_message +                         # 92 bytes
        eth_sig.v.to_bytes(1, 'big') +               # 1 byte (v) - Bob's signature
        eth_sig.r.to_bytes(32, 'big') +              # 32 bytes (r) - Bob's signature
        eth_sig.s.to_bytes(32, 'big') +              # 32 bytes (s) - Bob's signature
        (1).to_bytes(32, 'big')                      # 32 bytes
    )  # Total: 272 bytes exactly
    
    pq_sig = generate_epervier_signature(pq_message, 0)  # Use Alice's PQ key (correct)
    if not pq_sig:
        print("Failed to generate signature for ETH address mismatch test")
        return
    
    vectors.append({
        "test_name": "eth_address_mismatch",
        "description": "Test revert when ETH address in PQ message doesn't match recovered ETH signature",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_nonce": 1,
        "pq_message": "0x" + pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"],
            "cs1": pq_sig["cs1"],
            "cs2": pq_sig["cs2"],
            "hint": pq_sig["hint"]
        }
    })
    
    # Test 9: PQ fingerprint mismatch (index 9)
    print("Generating PQ fingerprint mismatch test...")
    # Create BaseETHRegistrationConfirmationMessage with Alice's fingerprint
    eth_confirm_message = create_base_eth_message(pq_fingerprint, 0)

    eth_sig = generate_eip712_signature(pq_fingerprint, 0, eth_priv_key, DOMAIN_SEPARATOR)
    
    # Create PQRegistrationConfirmationMessage with Alice's data but signed by Charlie
    pattern = "Confirm binding to ETH Address "
    pq_message = (
        domain_separator_bytes +                       # 32 bytes
        pattern.encode() +                             # 31 bytes
        eth_address_bytes +                           # 20 bytes
        eth_confirm_message +                         # 92 bytes
        eth_sig.v.to_bytes(1, 'big') +               # 1 byte (v)
        eth_sig.r.to_bytes(32, 'big') +              # 32 bytes (r)
        eth_sig.s.to_bytes(32, 'big') +              # 32 bytes (s)
        (0).to_bytes(32, 'big')                      # 32 bytes
    )  # Total: 272 bytes exactly

    pq_sig = generate_epervier_signature(pq_message, 2)  # Use Charlie's key (index 2)
    if not pq_sig:
        print("Failed to generate signature for PQ fingerprint mismatch test")
        return
    
    vectors.append({
        "test_name": "pq_fingerprint_mismatch",
        "description": "Test revert when PQ fingerprint in ETH signature doesn't match recovered PQ signature",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_nonce": 0,
        "pq_message": "0x" + pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"],
            "cs1": pq_sig["cs1"],
            "cs2": pq_sig["cs2"],
            "hint": pq_sig["hint"]
        }
    })
    
    # Test 10: Malformed message (wrong format) (index 10)
    print("Generating malformed message test...")
    # Create a malformed message that's 272 bytes but has wrong format
    malformed_message = b"short" + b'\x00' * 267  # 5 + 267 = 272 bytes but wrong format
    pq_sig = generate_epervier_signature(malformed_message, 0)
    if not pq_sig:
        print("Failed to generate signature for malformed message test")
        return
    
    vectors.append({
        "test_name": "malformed_message",
        "description": "Test revert when PQ confirmation message is malformed (wrong format)",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_nonce": 1,
        "pq_message": "0x" + malformed_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"],
            "cs1": pq_sig["cs1"],
            "cs2": pq_sig["cs2"],
            "hint": pq_sig["hint"]
        }
    })
    
    # Write the vectors to file
    with open(output_file, 'w') as f:
        json.dump({"confirm_registration_reverts": vectors}, f, indent=2)
    print(f"Generated {len(vectors)} confirmation revert test vectors")
    print(f"Written to: {output_file}")

def generate_simple_eth_address_mismatch_test():
    """Generate a simple ETH address mismatch test: Alice PQ + Bob ETH, but message contains Alice's ETH address"""
    
    # Output file path
    output_file = SCRIPT_DIR.parent.parent.parent / "test_vectors/revert/confirm_registration_revert_vectors.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    print("Generating simple ETH address mismatch test...")
    
    # Convert DOMAIN_SEPARATOR from hex string to bytes
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    
    # Alice's data
    alice_eth_priv_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    alice_account = Account.from_key(alice_eth_priv_key)
    alice_eth_address = alice_account.address
    alice_eth_address_bytes = bytes.fromhex(alice_eth_address[2:])
    
    # Bob's ETH key (for signing)
    bob_eth_priv_key = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
    
    # Fixed PQ fingerprint
    pq_fingerprint = "0x7b317f4d231cbc63de7c6c690ef4ba9c653437fb"
    
    # Create BaseETHRegistrationConfirmationMessage exactly as per schema (92 bytes)
    eth_confirm_message = create_base_eth_message(pq_fingerprint, 1)
    
    # Generate ETH signature using Bob's key (recovering Bob's address)
    eth_sig = generate_eip712_signature(pq_fingerprint, 1, bob_eth_priv_key, DOMAIN_SEPARATOR)
    
    # Create PQRegistrationConfirmationMessage with Alice's ETH address but Bob's signature
    pattern = "Confirm binding to ETH Address "
    pq_message = (
        domain_separator_bytes +                       # 32 bytes
        pattern.encode() +                             # 31 bytes
        alice_eth_address_bytes +                     # 20 bytes (Alice's address in message)
        eth_confirm_message +                         # 92 bytes
        eth_sig.v.to_bytes(1, 'big') +               # 1 byte (v) - Bob's signature
        eth_sig.r.to_bytes(32, 'big') +              # 32 bytes (r) - Bob's signature
        eth_sig.s.to_bytes(32, 'big') +              # 32 bytes (s) - Bob's signature
        (1).to_bytes(32, 'big')                      # 32 bytes
    )  # Total: 272 bytes exactly
    
    # Sign with Alice's PQ key (correct)
    pq_sig = generate_epervier_signature(pq_message, 0)  # Use Alice's PQ key (index 0)
    if not pq_sig:
        print("Failed to generate signature for ETH address mismatch test")
        return
    
    # Create the test vector
    vectors = [{
        "test_name": "eth_address_mismatch",
        "description": "Test revert when ETH address in PQ message doesn't match recovered ETH signature",
        "eth_address": alice_eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_nonce": 1,
        "pq_message": "0x" + pq_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"],
            "cs1": pq_sig["cs1"],
            "cs2": pq_sig["cs2"],
            "hint": pq_sig["hint"]
        }
    }]
    
    # Write the vectors to file
    with open(output_file, 'w') as f:
        json.dump({"confirm_registration_reverts": vectors}, f, indent=2)
    print(f"Generated ETH address mismatch test vector")
    print(f"Written to: {output_file}")

if __name__ == "__main__":
    generate_confirm_revert_vectors() 
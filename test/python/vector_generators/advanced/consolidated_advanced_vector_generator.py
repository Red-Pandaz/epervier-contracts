#!/usr/bin/env python3
"""
Consolidated Advanced Vector Generator

This generator combines all advanced test vector generation functionality from:
- advanced_vector_generator.py
- advanced_test_scenario_generator.py  
- advanced_working_vector_generator.py

All vectors are output to test/test_vectors/ with consistent naming:
- test1_*_vectors.json
- test2_*_vectors.json
- etc.

The generator supports all advanced test scenarios including:
- Registration flows with removals and retries
- Change ETH address flows with cancellations
- Unregistration flows with revocations
- Full lifecycle tests
- Cross-actor scenarios
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from eth_account import Account
from eth_utils import keccak, to_checksum_address
from eth_abi import encode
from tempfile import NamedTemporaryFile

# Add the parent directory to the path to import eip712_config
sys.path.append(str(Path(__file__).resolve().parents[2]))  # test/python
from eip712_config import DOMAIN_SEPARATOR, CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH, CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH, REMOVE_CHANGE_INTENT_TYPE_HASH

# Project root
project_root = Path(__file__).resolve().parents[4]

# Always use the absolute path for output
output_path = project_root / "test/test_vectors/advanced"
output_path.mkdir(parents=True, exist_ok=True)

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')

def load_actors_config() -> Dict[str, Any]:
    """Load actor configuration from the main config file"""
    config_file = project_root / "test" / "test_keys" / "actors_config.json"
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

# EIP-712 signing functions (matching basic generators)
def sign_registration_intent_eip712(salt: bytes, cs1: List[int], cs2: List[int], hint: int, base_pq_message: bytes, eth_nonce: int, private_key: str) -> Dict[str, Any]:
    """Sign registration intent using EIP-712 - matching basic generator format"""
    # Create the struct hash for the message components
    struct_hash = keccak(encode_packed(
        keccak(b"RegistrationIntent(bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,bytes basePQMessage,uint256 ethNonce)"),
        keccak(salt),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs1])),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs2])),
        hint.to_bytes(32, 'big'),
        keccak(base_pq_message),
        eth_nonce.to_bytes(32, 'big')
    ))
    
    # Create EIP712 digest with domain separator
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    digest = keccak(encode_packed(b'\x19\x01', domain_separator_bytes, struct_hash))
    
    # Sign the digest
    account = Account.from_key(private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}

def sign_registration_confirmation_eip712(pq_fingerprint: str, eth_nonce: int, private_key: str) -> Dict[str, Any]:
    """Sign registration confirmation using EIP-712 - matching basic generator format"""
    from eth_abi import encode
    
    # Create the struct hash for the message components using abi.encode (not encode_packed)
    struct_hash = keccak(encode([
        'bytes32', 'address', 'uint256'
    ], [
        keccak(b"RegistrationConfirmation(address pqFingerprint,uint256 ethNonce)"),
        pq_fingerprint,  # eth_abi.encode will handle the address properly
        eth_nonce
    ]))
    
    # Create EIP712 digest with domain separator
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    digest = keccak(encode_packed(b'\x19\x01', domain_separator_bytes, struct_hash))
    
    # Sign the digest
    account = Account.from_key(private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}

def sign_change_eth_address_intent_eip712(new_eth_address: str, pq_fingerprint: str, eth_nonce: int, private_key: str) -> dict:
    """Sign change ETH address intent using EIP-712"""
    from eth_utils import keccak, to_checksum_address
    from eth_abi import encode
    type_hash = bytes.fromhex(CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH[2:])
    new_eth_address_checksum = to_checksum_address(new_eth_address)
    pq_fingerprint_checksum = to_checksum_address(pq_fingerprint)
    # Use abi.encode like the contract implementation
    encoded_data = encode([
        'bytes32', 'address', 'address', 'uint256'
    ], [
        type_hash,
        new_eth_address_checksum,
        pq_fingerprint_checksum,
        eth_nonce
    ])
    struct_hash = keccak(encoded_data)
    domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    digest = keccak(b"\x19\x01" + domain_separator + struct_hash)
    print(f"DEBUG: Python new_eth_address: {new_eth_address}")
    print(f"DEBUG: Python pq_fingerprint: {pq_fingerprint}")
    print(f"DEBUG: Python eth_nonce: {eth_nonce}")
    print(f"DEBUG: Python type_hash: {type_hash.hex()}")
    print(f"DEBUG: Python struct_hash: {struct_hash.hex()}")
    print(f"DEBUG: Python domain_separator: {domain_separator.hex()}")
    print(f"DEBUG: Python digest: {digest.hex()}")
    # ... existing code ...
    account = Account.from_key(private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}

def sign_change_eth_address_confirmation_eip712(old_eth_address: str, pq_fingerprint: str, base_pq_message: bytes, salt: bytes, cs1: list, cs2: list, hint: int, eth_nonce: int, private_key: str) -> dict:
    """Sign change ETH address confirmation using EIP-712 - matching basic generator format"""
    from eth_utils import keccak, to_checksum_address
    from eth_abi import encode
    type_hash = bytes.fromhex(CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH[2:])
    old_eth_address_checksum = to_checksum_address(old_eth_address)
    pq_fingerprint_checksum = to_checksum_address(pq_fingerprint)
    # Use abi.encode like the contract implementation
    encoded_data = encode([
        'bytes32',
        'address',
        'address',
        'bytes32',  # keccak256(basePQMessage)
        'bytes32',  # keccak256(salt)
        'bytes32',  # keccak256(abi.encodePacked(cs1))
        'bytes32',  # keccak256(abi.encodePacked(cs2))
        'uint256',
        'uint256'
    ], [
        type_hash,
        old_eth_address_checksum,
        pq_fingerprint_checksum,
        keccak(base_pq_message),
        keccak(salt),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs1])),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs2])),
        hint,
        eth_nonce
    ])
    struct_hash = keccak(encoded_data)
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    digest = keccak(b'\x19\x01' + domain_separator_bytes + struct_hash)
    print(f"DEBUG: Python old_eth_address: {old_eth_address}")
    print(f"DEBUG: Python pq_fingerprint: {pq_fingerprint}")
    print(f"DEBUG: Python eth_nonce: {eth_nonce}")
    print(f"DEBUG: Python type_hash: {CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH}")
    print(f"DEBUG: Python struct_hash: {struct_hash.hex()}")
    print(f"DEBUG: Python domain_separator: {domain_separator_bytes.hex()}")
    print(f"DEBUG: Python digest: {digest.hex()}")
    account = Account.from_key(private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}

def sign_unregistration_intent_eip712(pq_fingerprint: str, eth_nonce: int, private_key: str) -> Dict[str, Any]:
    """Sign unregistration intent using EIP-712 - matching basic generator format"""
    from eth_abi import encode
    
    # Create the struct hash for the message components using abi.encode (like Solidity)
    struct_hash = keccak(encode([
        'bytes32', 'address', 'uint256'
    ], [
        keccak(b"UnregistrationIntent(address pqFingerprint,uint256 ethNonce)"),
        pq_fingerprint,
        eth_nonce
    ]))
    
    # Create EIP712 digest with domain separator
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    digest = keccak(encode_packed(b'\x19\x01', domain_separator_bytes, struct_hash))
    
    # Sign the digest
    account = Account.from_key(private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}

def sign_unregistration_confirmation_eip712(pq_fingerprint: str, base_pq_message: bytes, salt: bytes, cs1: List[int], cs2: List[int], hint: int, eth_nonce: int, private_key: str) -> Dict[str, Any]:
    """Sign unregistration confirmation using EIP-712 - matching basic generator format"""
    from eth_abi import encode
    
    # Create the struct hash for the message components using abi.encode like the contract
    encoded_data = encode([
        'bytes32', 'address', 'bytes32', 'bytes32', 'bytes32', 'bytes32', 'uint256', 'uint256'
    ], [
        keccak(b"UnregistrationConfirmation(address pqFingerprint,bytes basePQMessage,bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,uint256 ethNonce)"),
        bytes.fromhex(pq_fingerprint[2:]),  # Remove '0x' prefix
        keccak(base_pq_message),
        keccak(salt),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs1])),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs2])),
        hint,
        eth_nonce
    ])
    struct_hash = keccak(encoded_data)
    
    # Create EIP712 digest with domain separator
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    digest = keccak(encode_packed(b'\x19\x01', domain_separator_bytes, struct_hash))
    
    # Sign the digest
    account = Account.from_key(private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}

def sign_remove_change_intent_eip712(pq_fingerprint: str, eth_nonce: int, private_key: str) -> dict:
    """Sign remove change intent using EIP-712"""
    from eth_utils import keccak, to_checksum_address
    from eth_abi import encode
    type_hash = bytes.fromhex(REMOVE_CHANGE_INTENT_TYPE_HASH[2:])
    pq_fingerprint_checksum = to_checksum_address(pq_fingerprint)
    # Use abi.encode like the contract implementation - MUST include type_hash in struct hash
    encoded_data = encode([
        'bytes32', 'address', 'uint256'
    ], [
        type_hash,
        pq_fingerprint_checksum,
        eth_nonce
    ])
    struct_hash = keccak(encoded_data)
    
    # DEBUG: Print the values for comparison with Solidity
    print(f"DEBUG: Python pq_fingerprint: {pq_fingerprint}")
    print(f"DEBUG: Python eth_nonce: {eth_nonce}")
    print(f"DEBUG: Python type_hash: {type_hash.hex()}")
    print(f"DEBUG: Python struct_hash: {struct_hash.hex()}")
    
    # Create EIP-712 digest
    domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    digest = keccak(b'\x19\x01' + domain_separator + struct_hash)
    print(f"DEBUG: Python domain_separator: {domain_separator.hex()}")
    print(f"DEBUG: Python digest: {digest.hex()}")
    
    # Sign the digest
    account = Account.from_key(private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}

def generate_epervier_signature(message: bytes, actor: str) -> Dict[str, Any]:
    """Generate Epervier signature using the CLI"""
    actors = load_actors_config()["actors"]
    actor_config = actors[actor]
    
    sign_cli = str(project_root / "ETHFALCON" / "python-ref" / "sign_cli.py")
    privkey_path = str(project_root / "test" / "test_keys" / actor_config["pq_private_key_file"])
    venv_python = str(project_root / "ETHFALCON" / "python-ref" / "myenv" / "bin" / "python3")
    
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
            signature_data["salt"] = bytes.fromhex(line.split()[1])
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

# Message creation functions
def create_base_pq_registration_intent_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create base PQ registration intent message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Ensure 32 bytes
    return abi_encode_packed(
        domain_separator_bytes,
        "Intent to pair ETH Address ",
        eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

def create_eth_registration_intent_message(base_pq_message: bytes, salt: bytes, cs1: List[int], cs2: List[int], hint: int, eth_nonce: int) -> bytes:
    """Create ETH registration intent message"""
    pattern = b"Intent to pair Epervier Key"
    return (
        pattern +
        base_pq_message +
        salt +
        pack_uint256_array(cs1) +
        pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') +
        eth_nonce.to_bytes(32, 'big')
    )

def create_base_eth_registration_confirmation_message(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Create base ETH registration confirmation message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    pattern = b"Confirm bonding to Epervier Fingerprint "
    return (
        pattern +
        pq_fingerprint_bytes +
        eth_nonce.to_bytes(32, 'big')
    )

def create_pq_registration_confirmation_message(eth_address: str, base_eth_message: bytes, v: int, r: int, s: int, pq_nonce: int) -> bytes:
    """Create PQ registration confirmation message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    return abi_encode_packed(
        domain_separator_bytes,
        "Confirm bonding to ETH Address ",
        eth_address_bytes,
        base_eth_message,
        v.to_bytes(1, 'big'),
        r.to_bytes(32, 'big'),
        s.to_bytes(32, 'big'),
        pq_nonce.to_bytes(32, 'big')
    )

def create_base_eth_change_eth_address_intent_message(pq_fingerprint: str, new_eth_address: str, eth_nonce: int) -> bytes:
    """Create base ETH change address intent message - matching working generator format"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    new_eth_address_bytes = bytes.fromhex(new_eth_address[2:])  # Remove 0x prefix
    pattern = b"Intent to change ETH Address and bond with Epervier Fingerprint "
    pattern2 = b" to "
    return (
        pattern +
        pq_fingerprint_bytes +
        pattern2 +
        new_eth_address_bytes +
        eth_nonce.to_bytes(32, 'big')
    )

def create_pq_change_eth_address_intent_message(old_eth_address: str, new_eth_address: str, base_eth_message: bytes, v: int, r: int, s: int, pq_nonce: int) -> bytes:
    """Create PQ change address intent message - matching working generator format"""
    old_eth_address_bytes = bytes.fromhex(old_eth_address[2:])  # Remove 0x prefix
    new_eth_address_bytes = bytes.fromhex(new_eth_address[2:])  # Remove 0x prefix
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    return abi_encode_packed(
        domain_separator_bytes,
        "Intent to change bound ETH Address from ",
        old_eth_address_bytes,
        " to ",
        new_eth_address_bytes,
        base_eth_message,
        v.to_bytes(1, 'big'),
        r.to_bytes(32, 'big'),
        s.to_bytes(32, 'big'),
        pq_nonce.to_bytes(32, 'big')
    )

def create_base_pq_change_eth_address_confirm_message(old_eth_address: str, new_eth_address: str, pq_nonce: int) -> bytes:
    """Create base PQ change ETH address confirmation message - complete message for parseBasePQChangeETHAddressConfirmMessage"""
    old_eth_address_bytes = bytes.fromhex(old_eth_address[2:])  # Remove 0x prefix
    new_eth_address_bytes = bytes.fromhex(new_eth_address[2:])  # Remove 0x prefix
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    message_bytes = (
        domain_separator_bytes +
        b"Confirm changing bound ETH Address for Epervier Fingerprint from " +
        old_eth_address_bytes +
        b" to " +
        new_eth_address_bytes +
        pq_nonce.to_bytes(32, 'big')
    )
    return message_bytes

def create_eth_change_eth_address_confirmation_message(pq_fingerprint: str, base_pq_message: bytes, salt: bytes, cs1: list, cs2: list, hint: int, eth_nonce: int) -> bytes:
    """Create ETH change address confirmation message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    pattern = b"Confirm change ETH Address for Epervier Fingerprint "
    
    # Ensure base_pq_message is exactly 173 bytes as expected by Solidity parser
    if len(base_pq_message) > 173:
        # Truncate to 173 bytes
        base_pq_message = base_pq_message[:173]
    elif len(base_pq_message) < 173:
        # Pad with zeros to 173 bytes
        base_pq_message = base_pq_message + b'\x00' * (173 - len(base_pq_message))
    
    return (
        pattern +
        pq_fingerprint_bytes +
        base_pq_message +
        salt +
        pack_uint256_array(cs1) +
        pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') +
        eth_nonce.to_bytes(32, 'big')
    )

def create_base_eth_unregistration_intent_message(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Create base ETH unregistration intent message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    pattern = b"Intent to unregister from Epervier Fingerprint "
    return (
        pattern +
        pq_fingerprint_bytes +
        eth_nonce.to_bytes(32, 'big')
    )

def create_pq_unregistration_intent_message(eth_address: str, base_eth_message: bytes, v: int, r: int, s: int, pq_nonce: int) -> bytes:
    """Create PQ unregistration intent message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    return abi_encode_packed(
        domain_separator_bytes,
        "Intent to unregister from Epervier Fingerprint from address ",
        eth_address_bytes,
        base_eth_message,
        v.to_bytes(1, 'big'),
        r.to_bytes(32, 'big'),
        s.to_bytes(32, 'big'),
        pq_nonce.to_bytes(32, 'big')
    )

def create_base_pq_unregistration_confirm_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create base PQ unregistration confirmation message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    return abi_encode_packed(
        domain_separator_bytes,
        "Confirm unregistration from ETH Address ",
        eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

def create_eth_unregistration_confirmation_message(pq_fingerprint: str, base_pq_message: bytes, salt: bytes, cs1: list, cs2: list, hint: int, eth_nonce: int) -> bytes:
    """Create ETH unregistration confirmation message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    pattern = b"Confirm unregistration from Epervier Fingerprint "
    return (
        pattern +
        pq_fingerprint_bytes +
        base_pq_message +
        salt +
        pack_uint256_array(cs1) +
        pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') +
        eth_nonce.to_bytes(32, 'big')
    )

# Removal message functions
def create_eth_remove_registration_intent_message(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Create ETH remove registration intent message"""
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    pattern = b"Remove registration intent from Epervier Fingerprint "
    return (
        pattern +
        pq_fingerprint_bytes +
        eth_nonce.to_bytes(32, 'big')
    )

def create_pq_remove_registration_intent_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create PQ remove registration intent message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    return abi_encode_packed(
        domain_separator_bytes,
        "Remove registration intent from ETH Address ",
        eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

def create_eth_remove_change_intent_message(pq_fingerprint, eth_nonce):
    """Create ETH message for removing change ETH address intent (matches working generator)"""
    pattern = b"Remove change intent from Epervier Fingerprint "
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    return pattern + pq_fingerprint_bytes + eth_nonce.to_bytes(32, 'big')

def create_pq_remove_change_intent_message(domain_separator, eth_address, pq_nonce):
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    domain_separator_bytes = bytes.fromhex(domain_separator[2:]) if isinstance(domain_separator, str) else domain_separator
    return abi_encode_packed(
        domain_separator_bytes,
        "Remove change intent from ETH Address ",
        eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

def create_pq_remove_unregistration_intent_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create PQ remove unregistration intent message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
    return abi_encode_packed(
        domain_separator_bytes,
        "Remove unregistration intent from ETH Address ",
        eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

# Utility functions
def bytes_to_hex(obj):
    """Convert bytes objects to hex strings with 0x prefix"""
    if isinstance(obj, dict):
        return {k: bytes_to_hex(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [bytes_to_hex(item) for item in obj]
    elif isinstance(obj, bytes):
        return f"0x{obj.hex()}"
    elif isinstance(obj, str):
        # Check if it's a hex string without 0x prefix
        if len(obj) >= 64 and all(c in '0123456789abcdef' for c in obj.lower()):
            # It's likely a hex string, add 0x prefix
            return f"0x{obj}"
        else:
            return obj
    else:
        return obj

def find_bytes(obj, path="root"):
    """Check if there are any bytes objects in the data structure"""
    if isinstance(obj, bytes):
        print(f"Found bytes at {path}")
        return True
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if find_bytes(v, f"{path}.{k}"):
                return True
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            if find_bytes(item, f"{path}[{i}]"):
                return True
    return False

class AdvancedVectorGenerator:
    def __init__(self):
        # Load actors from the main config
        self.actors_config = load_actors_config()
        self.actors = self.actors_config["actors"]
    
    def generate_registration_intent_vector(self, actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a registration intent vector with custom nonces"""
        actor_data = self.actors[actor]

        # Create base PQ message
        base_pq_message = create_base_pq_registration_intent_message(
            actor_data["eth_address"], 
            pq_nonce
        )

        # Generate PQ signature
        pq_signature = generate_epervier_signature(base_pq_message, actor)

        # Create full ETH message
        eth_message = create_eth_registration_intent_message(
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            eth_nonce
        )

        # Generate ETH signature
        eth_signature = sign_registration_intent_eip712(
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            base_pq_message,
            eth_nonce,
            actor_data["eth_private_key"]
        )

        return {
            "actor": actor,
            "eth_address": actor_data["eth_address"],
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_cross_actor_registration_intent_vector(self, pq_actor: str, eth_actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a registration intent vector where one actor's PQ key signs for another actor's ETH address"""
        pq_actor_data = self.actors[pq_actor]
        eth_actor_data = self.actors[eth_actor]

        # Create base PQ message with the target ETH address
        base_pq_message = create_base_pq_registration_intent_message(
            eth_actor_data["eth_address"], 
            pq_nonce
        )

        # Generate PQ signature using the PQ actor's key
        pq_signature = generate_epervier_signature(base_pq_message, pq_actor)

        # Create full ETH message
        eth_message = create_eth_registration_intent_message(
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            eth_nonce
        )

        # Generate ETH signature using the ETH actor's key
        eth_signature = sign_registration_intent_eip712(
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            base_pq_message,
            eth_nonce,
            eth_actor_data["eth_private_key"]
        )

        return {
            "pq_actor": pq_actor,
            "eth_actor": eth_actor,
            "eth_address": eth_actor_data["eth_address"],
            "pq_fingerprint": pq_actor_data["pq_fingerprint"],
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_registration_confirmation_vector(self, actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a registration confirmation vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Create base ETH confirmation message
        base_eth_message = create_base_eth_registration_confirmation_message(
            actor_data["pq_fingerprint"],
            eth_nonce
        )
        
        # Generate ETH signature
        eth_signature = sign_registration_confirmation_eip712(
            actor_data["pq_fingerprint"],
            eth_nonce,
            actor_data["eth_private_key"]
        )
        
        # Create PQ confirmation message
        pq_message = create_pq_registration_confirmation_message(
            actor_data["eth_address"],
            base_eth_message,
            eth_signature["v"],
            eth_signature["r"],
            eth_signature["s"],
            pq_nonce
        )
        
        # Generate PQ signature
        pq_signature = generate_epervier_signature(pq_message, actor)
        
        return {
            "actor": actor,
            "eth_address": actor_data["eth_address"],
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "eth_signature": eth_signature,
            "pq_message": pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_cross_actor_registration_confirmation_vector(self, eth_actor: str, target_eth_actor: str, eth_nonce: int, pq_nonce: int, pq_actor: str = None) -> Dict[str, Any]:
        """Generate a registration confirmation vector where one actor's ETH key confirms for another actor's ETH address"""
        eth_actor_data = self.actors[eth_actor]
        target_eth_actor_data = self.actors[target_eth_actor]
        
        # For cross-actor confirmation, we need to determine which PQ fingerprint to use
        # If pq_actor is provided, use that actor's PQ fingerprint
        # Otherwise, default to the target_eth_actor's PQ fingerprint (for backward compatibility)
        if pq_actor is not None:
            pq_actor_data = self.actors[pq_actor]
            pq_fingerprint = pq_actor_data["pq_fingerprint"]
        else:
            # Default to target_eth_actor's PQ fingerprint for backward compatibility
            target_eth_actor_data = self.actors[target_eth_actor]
            pq_fingerprint = target_eth_actor_data["pq_fingerprint"]
        
        # Create base ETH confirmation message with the correct PQ fingerprint
        base_eth_message = create_base_eth_registration_confirmation_message(
            pq_fingerprint,  # Use the correct PQ fingerprint
            eth_nonce
        )
        
        # Generate ETH signature using the ETH actor's key
        eth_signature = sign_registration_confirmation_eip712(
            pq_fingerprint,
            eth_nonce,
            eth_actor_data["eth_private_key"]
        )
        
        # Create PQ confirmation message with the target's ETH address
        pq_message = create_pq_registration_confirmation_message(
            target_eth_actor_data["eth_address"],  # Use target's ETH address in PQ message
            base_eth_message,
            eth_signature["v"],
            eth_signature["r"],
            eth_signature["s"],
            pq_nonce
        )
        
        # Generate PQ signature using the correct PQ key
        if pq_actor is not None:
            pq_signature = generate_epervier_signature(pq_message, pq_actor)
        else:
            pq_signature = generate_epervier_signature(pq_message, target_eth_actor)
        
        return {
            "eth_actor": eth_actor,
            "target_eth_actor": target_eth_actor,
            "eth_address": target_eth_actor_data["eth_address"],
            "pq_fingerprint": pq_fingerprint,  # Return the correct PQ fingerprint
            "base_eth_message": base_eth_message.hex(),
            "eth_signature": eth_signature,
            "pq_message": pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_change_eth_address_intent_vector(self, actor: str, new_eth_address: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a change ETH address intent vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Handle actor name as new ETH address
        if new_eth_address in self.actors:
            new_eth_actor_data = self.actors[new_eth_address]
            resolved_new_eth_address = new_eth_actor_data["eth_address"]
            new_eth_private_key = new_eth_actor_data["eth_private_key"]
            new_actor = new_eth_address
        else:
            # Use the actor's own private key if new_eth_address is a direct address
            resolved_new_eth_address = new_eth_address
            new_eth_private_key = actor_data["eth_private_key"]
            new_actor = actor
        
        # Create base ETH change intent message
        base_eth_message = create_base_eth_change_eth_address_intent_message(
            actor_data["pq_fingerprint"],
            resolved_new_eth_address,
            eth_nonce
        )
        
        # Generate ETH signature with the new ETH address's private key
        eth_signature = sign_change_eth_address_intent_eip712(
            resolved_new_eth_address,
            actor_data["pq_fingerprint"],
            eth_nonce,
            new_eth_private_key
        )
        
        # Create PQ change intent message
        pq_message = create_pq_change_eth_address_intent_message(
            actor_data["eth_address"],
            resolved_new_eth_address,
            base_eth_message,
            eth_signature["v"],
            eth_signature["r"],
            eth_signature["s"],
            pq_nonce
        )
        
        # Generate PQ signature
        pq_signature = generate_epervier_signature(pq_message, actor)
        
        return {
            "current_actor": actor,
            "new_actor": new_actor,
            "old_eth_address": actor_data["eth_address"],
            "new_eth_address": resolved_new_eth_address,
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": pq_message.hex(),
            "eth_signature": eth_signature,
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_change_eth_address_confirmation_vector(self, actor: str, new_eth_address: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a change ETH address confirmation vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Handle actor name as new ETH address
        if new_eth_address in self.actors:
            new_eth_actor_data = self.actors[new_eth_address]
            resolved_new_eth_address = new_eth_actor_data["eth_address"]
            new_eth_private_key = new_eth_actor_data["eth_private_key"]
            new_actor = new_eth_address
        else:
            # Use the actor's own private key if new_eth_address is a direct address
            resolved_new_eth_address = new_eth_address
            new_eth_private_key = actor_data["eth_private_key"]
            new_actor = actor
        
        # Create base PQ change confirmation message
        base_pq_message = create_base_pq_change_eth_address_confirm_message(
            actor_data["eth_address"],
            resolved_new_eth_address,
            pq_nonce
        )
        
        # Generate PQ signature
        pq_signature = generate_epervier_signature(base_pq_message, actor)
        
        # Create ETH change confirmation message
        eth_message = create_eth_change_eth_address_confirmation_message(
            actor_data["pq_fingerprint"],
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            eth_nonce
        )
        
        # Generate ETH signature
        eth_signature = sign_change_eth_address_confirmation_eip712(
            actor_data["eth_address"],
            actor_data["pq_fingerprint"],
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            eth_nonce,
            new_eth_private_key
        )
        
        return {
            "current_actor": actor,
            "new_actor": new_actor,
            "old_eth_address": actor_data["eth_address"],
            "new_eth_address": resolved_new_eth_address,
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_unregistration_intent_vector(self, actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate an unregistration intent vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Create base ETH unregistration intent message
        base_eth_message = create_base_eth_unregistration_intent_message(
            actor_data["pq_fingerprint"],
            eth_nonce
        )
        
        # Generate ETH signature
        eth_signature = sign_unregistration_intent_eip712(
            actor_data["pq_fingerprint"],
            eth_nonce,
            actor_data["eth_private_key"]
        )
        
        # Create PQ unregistration intent message
        pq_message = create_pq_unregistration_intent_message(
            actor_data["eth_address"],
            base_eth_message,
            eth_signature["v"],
            eth_signature["r"],
            eth_signature["s"],
            pq_nonce
        )
        
        # Generate PQ signature
        pq_signature = generate_epervier_signature(pq_message, actor)
        
        return {
            "actor": actor,
            "eth_address": actor_data["eth_address"],
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "eth_signature": eth_signature,
            "pq_message": pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_cross_actor_unregistration_intent_vector(self, pq_actor: str, eth_actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a cross-actor unregistration intent vector"""
        pq_actor_data = self.actors[pq_actor]
        eth_actor_data = self.actors[eth_actor]

        # Create base ETH unregistration intent message with the PQ fingerprint
        base_eth_message = create_base_eth_unregistration_intent_message(
            pq_actor_data["pq_fingerprint"],
            eth_nonce
        )

        # Generate ETH signature using the ETH actor's key
        eth_signature = sign_unregistration_intent_eip712(
            pq_actor_data["pq_fingerprint"],
            eth_nonce,
            eth_actor_data["eth_private_key"]
        )

        # Create PQ unregistration intent message with the ETH address
        pq_message = create_pq_unregistration_intent_message(
            eth_actor_data["eth_address"],
            base_eth_message,
            eth_signature["v"],
            eth_signature["r"],
            eth_signature["s"],
            pq_nonce
        )

        # Generate PQ signature using the PQ actor's key
        pq_signature = generate_epervier_signature(pq_message, pq_actor)

        return {
            "pq_actor": pq_actor,
            "eth_actor": eth_actor,
            "eth_address": eth_actor_data["eth_address"],
            "pq_fingerprint": pq_actor_data["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "eth_signature": eth_signature,
            "pq_message": pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_unregistration_confirmation_vector(self, actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate an unregistration confirmation vector with custom nonces"""
        actor_data = self.actors[actor]
        
        # Create base PQ unregistration confirmation message
        base_pq_message = create_base_pq_unregistration_confirm_message(
            actor_data["eth_address"],
            pq_nonce
        )
        
        # Generate PQ signature
        pq_signature = generate_epervier_signature(base_pq_message, actor)
        
        # Create ETH unregistration confirmation message
        eth_message = create_eth_unregistration_confirmation_message(
            actor_data["pq_fingerprint"],
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            eth_nonce
        )
        
        # Generate ETH signature
        eth_signature = sign_unregistration_confirmation_eip712(
            actor_data["pq_fingerprint"],
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            eth_nonce,
            actor_data["eth_private_key"]
        )
        
        return {
            "actor": actor,
            "eth_address": actor_data["eth_address"],
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_cross_actor_unregistration_confirmation_vector(self, pq_actor: str, eth_actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a cross-actor unregistration confirmation vector"""
        pq_actor_data = self.actors[pq_actor]
        eth_actor_data = self.actors[eth_actor]

        # Create base PQ unregistration confirmation message
        base_pq_message = create_base_pq_unregistration_confirm_message(
            eth_actor_data["eth_address"],  # Use the ETH actor's address
            pq_nonce
        )

        # Generate PQ signature using the working approach from basic generator
        pq_signature = self.sign_with_pq_key_working(base_pq_message, pq_actor_data["pq_private_key_file"])
        if pq_signature is None:
            raise Exception(f"Failed to generate PQ signature for {pq_actor}")

        # Create ETH unregistration confirmation message
        eth_message = create_eth_unregistration_confirmation_message(
            pq_actor_data["pq_fingerprint"],
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            eth_nonce
        )

        # Generate ETH signature
        eth_signature = sign_unregistration_confirmation_eip712(
            pq_actor_data["pq_fingerprint"],
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            eth_nonce,
            eth_actor_data["eth_private_key"]
        )

        return {
            "actor": pq_actor,
            "eth_actor": eth_actor,
            "eth_address": eth_actor_data["eth_address"],
            "pq_fingerprint": pq_actor_data["pq_fingerprint"],
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": {
                "salt": pq_signature["salt"].hex(),
                "cs1": [hex(x) for x in pq_signature["cs1"]],
                "cs2": [hex(x) for x in pq_signature["cs2"]],
                "hint": pq_signature["hint"]
            },
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
    
    def generate_removal_vector(self, actor: str, removal_type: str, eth_nonce: int, pq_nonce: int, target_pq_fingerprint: str = None) -> Dict[str, Any]:
        """Generate a removal vector for various types of removals"""
        actor_data = self.actors[actor]
        
        if removal_type == "registration_pq":
            # PQ removes registration intent
            message = create_pq_remove_registration_intent_message(
                actor_data["eth_address"],
                pq_nonce
            )
            signature = generate_epervier_signature(message, actor)
            return {
                "actor": actor,
                "eth_address": actor_data["eth_address"],
                "pq_fingerprint": actor_data["pq_fingerprint"],
                "pq_message": message.hex(),
                "pq_signature": signature,
                "pq_nonce": pq_nonce
            }
        elif removal_type == "registration_eth":
            # ETH removes registration intent
            message = create_eth_remove_registration_intent_message(
                actor_data["pq_fingerprint"],
                eth_nonce
            )
            signature = generate_eth_signature(message, actor_data["eth_private_key"])
            return {
                "actor": actor,
                "eth_address": actor_data["eth_address"],
                "pq_fingerprint": actor_data["pq_fingerprint"],
                "message": message.hex(),
                "signature": signature,
                "eth_nonce": eth_nonce
            }
        elif removal_type == "change_pq":
            # PQ removes change intent - need to determine which change intent is being canceled
            # For test4, the PQ removal has pq_nonce: 3, which means it's canceling the change intent with pq_nonce: 2 (Alice -> Bob)
            # So we need to use Bob's address, not Alice's address
            
            # Determine the target ETH address based on the scenario
            target_eth_address = None
            if actor == "alice" and pq_nonce == 3:
                # This is canceling the Alice -> Bob change intent (pq_nonce: 2)
                target_eth_address = self.actors["bob"]["eth_address"]
            elif actor == "alice" and pq_nonce == 4:
                # This is canceling the Alice -> Charlie change intent (pq_nonce: 3)
                target_eth_address = self.actors["charlie"]["eth_address"]
            else:
                # Default to actor's current address if we can't determine
                target_eth_address = actor_data["eth_address"]
            
            message = create_pq_remove_change_intent_message(
                DOMAIN_SEPARATOR,
                target_eth_address,
                pq_nonce
            )
            signature = generate_epervier_signature(message, actor)
            return {
                "actor": actor,
                "eth_address": target_eth_address,
                "pq_fingerprint": actor_data["pq_fingerprint"],
                "message": message.hex(),
                "signature": signature,
                "pq_nonce": pq_nonce
            }
        elif removal_type == "change_eth":
            # ETH removes change intent
            # Handle target_pq_fingerprint - if it's an actor name, get their PQ fingerprint
            if target_pq_fingerprint and target_pq_fingerprint in self.actors:
                target_pq_fingerprint = self.actors[target_pq_fingerprint]["pq_fingerprint"]
            else:
                target_pq_fingerprint = target_pq_fingerprint or actor_data["pq_fingerprint"]
            
            # Create the message in the format expected by the contract
            # Format: "Remove change intent from Epervier Fingerprint " + pqFingerprint + ethNonce
            message_bytes = create_eth_remove_change_intent_message(
                target_pq_fingerprint,
                eth_nonce
            )
            
            # Use EIP-712 signing for the struct hash
            signature = sign_remove_change_intent_eip712(
                target_pq_fingerprint,
                eth_nonce,
                actor_data["eth_private_key"]
            )
            
            return {
                "actor": actor,
                "eth_address": actor_data["eth_address"],
                "pq_fingerprint": target_pq_fingerprint,
                "message": message_bytes.hex(),
                "signature": signature,
                "eth_nonce": eth_nonce
            }
        elif removal_type == "unregistration":
            # PQ removes unregistration intent
            message = create_pq_remove_unregistration_intent_message(
                actor_data["eth_address"],
                pq_nonce
            )
            signature = generate_epervier_signature(message, actor)
            return {
                "actor": actor,
                "eth_address": actor_data["eth_address"],
                "pq_fingerprint": actor_data["pq_fingerprint"],
                "message": message.hex(),
                "signature": signature,
                "pq_nonce": pq_nonce
            }
        else:
            raise ValueError(f"Unknown removal type: {removal_type}")
    
    def generate_scenario_vectors(self, scenario_name: str, scenario_config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate all vectors for a given scenario"""
        vectors = {}
        
        # Generate registration intent vectors
        if "registration_intent" in scenario_config:
            config = scenario_config["registration_intent"]
            if isinstance(config, list):
                # Handle multiple registration intents
                vectors["registration_intent"] = []
                for intent_config in config:
                    if "pq_actor" in intent_config and "eth_actor" in intent_config:
                        # Cross-actor registration intent
                        vector = self.generate_cross_actor_registration_intent_vector(
                            intent_config["pq_actor"],
                            intent_config["eth_actor"],
                            intent_config["eth_nonce"],
                            intent_config["pq_nonce"]
                        )
                    else:
                        # Standard registration intent
                        vector = self.generate_registration_intent_vector(
                            intent_config["actor"],
                            intent_config["eth_nonce"],
                            intent_config["pq_nonce"]
                        )
                    vectors["registration_intent"].append(vector)
            else:
                # Single registration intent
                if "pq_actor" in config and "eth_actor" in config:
                    # Cross-actor registration intent
                    vector = self.generate_cross_actor_registration_intent_vector(
                        config["pq_actor"],
                        config["eth_actor"],
                        config["eth_nonce"],
                        config["pq_nonce"]
                    )
                else:
                    # Standard registration intent
                    vector = self.generate_registration_intent_vector(
                        config["actor"],
                        config["eth_nonce"],
                        config["pq_nonce"]
                    )
                vectors["registration_intent"] = vector
        
        # Generate registration confirmation vectors
        if "registration_confirmation" in scenario_config:
            config = scenario_config["registration_confirmation"]
            if isinstance(config, list):
                # Handle multiple registration confirmations
                vectors["registration_confirmation"] = []
                for confirm_config in config:
                    if "eth_actor" in confirm_config and "target_eth_actor" in confirm_config:
                        # Cross-actor confirmation
                        pq_actor = confirm_config.get("pq_actor")  # Get pq_actor if present
                        vector = self.generate_cross_actor_registration_confirmation_vector(
                            confirm_config["eth_actor"],
                            confirm_config["target_eth_actor"],
                            confirm_config["eth_nonce"],
                            confirm_config["pq_nonce"],
                            pq_actor  # Pass the pq_actor parameter if present
                        )
                    else:
                        # Standard confirmation
                        vector = self.generate_registration_confirmation_vector(
                            confirm_config["actor"],
                            confirm_config["eth_nonce"],
                            confirm_config["pq_nonce"]
                        )
                    vectors["registration_confirmation"].append(vector)
            else:
                # Single registration confirmation
                if "eth_actor" in config and "target_eth_actor" in config:
                    # Cross-actor confirmation
                    pq_actor = config.get("pq_actor")  # Get pq_actor if present
                    vector = self.generate_cross_actor_registration_confirmation_vector(
                        config["eth_actor"],
                        config["target_eth_actor"],
                        config["eth_nonce"],
                        config["pq_nonce"],
                        pq_actor  # Pass the pq_actor parameter if present
                    )
                else:
                    # Standard confirmation
                    vector = self.generate_registration_confirmation_vector(
                        config["actor"],
                        config["eth_nonce"],
                        config["pq_nonce"]
                    )
                vectors["registration_confirmation"] = vector
        
        # Generate change ETH address intent vectors
        if "change_eth_address_intent" in scenario_config:
            config = scenario_config["change_eth_address_intent"]
            if isinstance(config, list):
                # Handle multiple change intents
                vectors["change_eth_address_intent"] = []
                for change_config in config:
                    vector = self.generate_change_eth_address_intent_vector(
                        change_config["actor"],
                        change_config["new_eth_address"],
                        change_config["eth_nonce"],
                        change_config["pq_nonce"]
                    )
                    vectors["change_eth_address_intent"].append(vector)
            else:
                # Single change intent
                vector = self.generate_change_eth_address_intent_vector(
                    config["actor"],
                    config["new_eth_address"],
                    config["eth_nonce"],
                    config["pq_nonce"]
                )
                vectors["change_eth_address_intent"] = vector
        
        # Generate change ETH address confirmation vectors
        if "change_eth_address_confirmation" in scenario_config:
            config = scenario_config["change_eth_address_confirmation"]
            if isinstance(config, list):
                # Handle multiple change confirmations
                vectors["change_eth_address_confirmation"] = []
                for change_config in config:
                    vector = self.generate_change_eth_address_confirmation_vector(
                        change_config["actor"],
                        change_config["new_eth_address"],
                        change_config["eth_nonce"],
                        change_config["pq_nonce"]
                    )
                    vectors["change_eth_address_confirmation"].append(vector)
            else:
                # Single change confirmation
                vector = self.generate_change_eth_address_confirmation_vector(
                    config["actor"],
                    config["new_eth_address"],
                    config["eth_nonce"],
                    config["pq_nonce"]
                )
                vectors["change_eth_address_confirmation"] = vector
        
        # Generate unregistration intent vectors
        if "unregistration_intent" in scenario_config:
            config = scenario_config["unregistration_intent"]
            if isinstance(config, list):
                # Handle multiple unregistration intents
                vectors["unregistration_intent"] = []
                for unreg_config in config:
                    if "pq_actor" in unreg_config and "eth_actor" in unreg_config:
                        # Cross-actor unregistration intent
                        vector = self.generate_cross_actor_unregistration_intent_vector(
                            unreg_config["pq_actor"],
                            unreg_config["eth_actor"],
                            unreg_config["eth_nonce"],
                            unreg_config["pq_nonce"]
                        )
                    else:
                        # Standard unregistration intent
                        vector = self.generate_unregistration_intent_vector(
                            unreg_config["actor"],
                            unreg_config["eth_nonce"],
                            unreg_config["pq_nonce"]
                        )
                    vectors["unregistration_intent"].append(vector)
            else:
                # Single unregistration intent
                if "pq_actor" in config and "eth_actor" in config:
                    # Cross-actor unregistration intent
                    vector = self.generate_cross_actor_unregistration_intent_vector(
                        config["pq_actor"],
                        config["eth_actor"],
                        config["eth_nonce"],
                        config["pq_nonce"]
                    )
                else:
                    # Standard unregistration intent
                    vector = self.generate_unregistration_intent_vector(
                        config["actor"],
                        config["eth_nonce"],
                        config["pq_nonce"]
                    )
                vectors["unregistration_intent"] = vector
        
        # Generate unregistration confirmation vectors
        if "unregistration_confirmation" in scenario_config:
            config = scenario_config["unregistration_confirmation"]
            if isinstance(config, list):
                # Handle multiple unregistration confirmations
                vectors["unregistration_confirmation"] = []
                for unreg_config in config:
                    if "pq_actor" in unreg_config and "eth_actor" in unreg_config:
                        # Cross-actor unregistration confirmation
                        vector = self.generate_cross_actor_unregistration_confirmation_vector(
                            unreg_config["pq_actor"],
                            unreg_config["eth_actor"],
                            unreg_config["eth_nonce"],
                            unreg_config["pq_nonce"]
                        )
                    else:
                        # Standard unregistration confirmation
                        vector = self.generate_unregistration_confirmation_vector(
                            unreg_config["actor"],
                            unreg_config["eth_nonce"],
                            unreg_config["pq_nonce"]
                        )
                    vectors["unregistration_confirmation"].append(vector)
            else:
                # Single unregistration confirmation
                if "pq_actor" in config and "eth_actor" in config:
                    # Cross-actor unregistration confirmation
                    vector = self.generate_cross_actor_unregistration_confirmation_vector(
                        config["pq_actor"],
                        config["eth_actor"],
                        config["eth_nonce"],
                        config["pq_nonce"]
                    )
                else:
                    # Standard unregistration confirmation
                    vector = self.generate_unregistration_confirmation_vector(
                        config["actor"],
                        config["eth_nonce"],
                        config["pq_nonce"]
                    )
                vectors["unregistration_confirmation"] = vector
        
        # Generate removal vectors
        for removal_type in ["registration_pq_removal", "registration_eth_removal", "change_pq_removal", "change_eth_removal", "unregistration_removal"]:
            if removal_type in scenario_config:
                config = scenario_config[removal_type]
                if isinstance(config, list):
                    # Handle multiple removals
                    vectors[removal_type] = []
                    for removal_config in config:
                        vector = self.generate_removal_vector(
                            removal_config["actor"],
                            removal_type.replace("_removal", ""),
                            removal_config["eth_nonce"],
                            removal_config["pq_nonce"],
                            removal_config.get("target_pq_fingerprint")
                        )
                        vectors[removal_type].append(vector)
                else:
                    # Single removal
                    vector = self.generate_removal_vector(
                        config["actor"],
                        removal_type.replace("_removal", ""),
                        config["eth_nonce"],
                        config["pq_nonce"],
                        config.get("target_pq_fingerprint")
                    )
                    vectors[removal_type] = vector
        
        # Generate final registration intent vectors (for test 9)
        if "final_registration_intent" in scenario_config:
            vectors["final_registration_intent"] = []
            for config in scenario_config["final_registration_intent"]:
                if "pq_actor" in config and "eth_actor" in config:
                    # Cross-actor registration intent
                    vector = self.generate_cross_actor_registration_intent_vector(
                        config["pq_actor"],
                        config["eth_actor"],
                        config["eth_nonce"],
                        config["pq_nonce"]
                    )
                else:
                    # Standard registration intent
                    vector = self.generate_registration_intent_vector(
                        config["actor"],
                        config["eth_nonce"],
                        config["pq_nonce"]
                    )
                vectors["final_registration_intent"].append(vector)
        
        # Generate final registration confirmation vectors (for test 9)
        if "final_registration_confirmation" in scenario_config:
            vectors["final_registration_confirmation"] = []
            for config in scenario_config["final_registration_confirmation"]:
                if "pq_actor" in config and "eth_actor" in config:
                    # Cross-actor confirmation with pq_actor and eth_actor
                    vector = self.generate_cross_actor_registration_confirmation_vector(
                        config["eth_actor"],
                        config["eth_actor"],  # target_eth_actor is the same as eth_actor
                        config["eth_nonce"],
                        config["pq_nonce"],
                        config["pq_actor"]  # Pass the pq_actor parameter
                    )
                elif "eth_actor" in config and "target_eth_actor" in config:
                    # Cross-actor confirmation with eth_actor and target_eth_actor
                    pq_actor = config.get("pq_actor")  # Get pq_actor if present
                    vector = self.generate_cross_actor_registration_confirmation_vector(
                        config["eth_actor"],
                        config["target_eth_actor"],
                        config["eth_nonce"],
                        config["pq_nonce"],
                        pq_actor  # Pass the pq_actor parameter if present
                    )
                else:
                    # Standard confirmation
                    vector = self.generate_registration_confirmation_vector(
                        config["actor"],
                        config["eth_nonce"],
                        config["pq_nonce"]
                    )
                vectors["final_registration_confirmation"].append(vector)
        
        return vectors
    
    def generate_bob_confirmation_vector(self) -> Dict[str, Any]:
        """Generate a proper confirmation vector for Bob with nonce 2 (ETH) and nonce 1 (PQ)"""
        actor = "bob"
        actor_data = self.actors[actor]
        
        # For confirmation, we need ETH nonce 2 and PQ nonce 1
        eth_nonce = 2
        pq_nonce = 1
        
        # Create the confirmation message format exactly like the working vectors
        eth_address_bytes = bytes.fromhex(actor_data["eth_address"][2:])  # Remove 0x prefix
        pq_fingerprint_bytes = bytes.fromhex(actor_data["pq_fingerprint"][2:])  # Remove 0x prefix
        
        # Construct the base ETH message (no domain separator)
        base_eth_message = (
            b"Confirm bonding to Epervier Fingerprint " +
            pq_fingerprint_bytes +
            eth_nonce.to_bytes(32, 'big')
        )

        # Generate a real ETH signature using Bob's ETH private key with EIP-712
        eth_signature = sign_registration_confirmation_eip712(
            actor_data["pq_fingerprint"],
            eth_nonce,
            actor_data["eth_private_key"]
        )

        pq_message = (
            bytes.fromhex(DOMAIN_SEPARATOR[2:]) +
            b"Confirm bonding to ETH Address " +
            eth_address_bytes +
            base_eth_message +
            eth_signature["v"].to_bytes(1, 'big') +
            eth_signature["r"].to_bytes(32, 'big') +
            eth_signature["s"].to_bytes(32, 'big') +
            pq_nonce.to_bytes(32, 'big')
        )
        
        # Generate PQ confirmation signature
        pq_confirmation_signature = generate_epervier_signature(pq_message, actor)
        
        return {
            "actor": actor,
            "eth_address": actor_data["eth_address"],
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "pq_message": pq_message.hex(),
            "pq_signature": pq_confirmation_signature
        }
    
    def sign_with_pq_key_working(self, base_pq_message: bytes, pq_private_key_file: str) -> Optional[Dict[str, Any]]:
        """Sign with PQ key using the working approach from basic generator"""
        from tempfile import NamedTemporaryFile
        import os
        import subprocess
        
        # Write message to temp file
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
            return None
        return out

    def sign_with_eth_key(self, eth_message: bytes, eth_private_key: str) -> Dict[str, Any]:
        """Sign with ETH key using Ethereum's personal_sign format"""
        eth_message_length = len(eth_message)
        eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + eth_message
        eth_message_hash = keccak(eth_signed_message)
        account = Account.from_key(eth_private_key)
        sig = Account._sign_hash(eth_message_hash, private_key=account.key)
        return {"v": sig.v, "r": sig.r, "s": sig.s}

def main():
    """Generate all advanced test vectors with consistent naming and output paths"""
    print("Generating consolidated advanced test vectors...")
    
    generator = AdvancedVectorGenerator()
    
    # Define all scenarios with consistent naming
    scenarios = [
        {
            "name": "test1_eth_retry",
            "config": {
                "registration_intent": [
                    {"actor": "alice", "eth_nonce": 0, "pq_nonce": 0}
                ],
                "removal_registration_pq": [
                    {"actor": "alice", "eth_nonce": 1, "pq_nonce": 1}
                ],
                "registration_intent_nonce2": [
                    {"actor": "alice", "eth_nonce": 1, "pq_nonce": 2}
                ],
                "registration_confirmation_nonce3": [
                    {"actor": "alice", "eth_nonce": 2, "pq_nonce": 3}
                ]
            }
        },
        {
            "name": "test2_pq_retry",
            "config": {
                "removal_registration_eth": [
                    {"actor": "bob", "removal_type": "registration_eth", "eth_nonce": 2, "pq_nonce": 0}
                ],
                "registration_intent": [
                    {"actor": "bob", "eth_nonce": 2, "pq_nonce": 1}
                ],
                "registration_confirmation": [
                    {"actor": "bob", "eth_nonce": 3, "pq_nonce": 2}
                ]
            }
        },
        {
            "name": "test4_pq_cancels_change_eth",
            "config": {
                "registration_intent": {"actor": "alice", "eth_nonce": 0, "pq_nonce": 0},
                "registration_confirmation": {"actor": "alice", "eth_nonce": 1, "pq_nonce": 1},
                "change_eth_address_intent": [
                    {"actor": "alice", "new_eth_address": "bob", "eth_nonce": 0, "pq_nonce": 2},
                    {"actor": "alice", "new_eth_address": "charlie", "eth_nonce": 0, "pq_nonce": 4}
                ],
                "removal_change_pq": [
                    {"actor": "alice", "eth_nonce": 2, "pq_nonce": 3}
                ],
                "change_eth_address_confirmation": [
                    {"actor": "alice", "new_eth_address": "charlie", "eth_nonce": 1, "pq_nonce": 5}
                ]
            }
        },
        {
            "name": "test5_eth_cancels_change_eth",
            "config": {
                "registration_intent": {"actor": "alice", "eth_nonce": 0, "pq_nonce": 0},
                "registration_confirmation": {"actor": "alice", "eth_nonce": 1, "pq_nonce": 1},
                "change_eth_address_intent": [
                    {"actor": "alice", "new_eth_address": "bob", "eth_nonce": 0, "pq_nonce": 2},
                    {"actor": "alice", "new_eth_address": "charlie", "eth_nonce": 0, "pq_nonce": 3}
                ],
                "change_eth_address_confirmation": [
                    {"actor": "alice", "new_eth_address": "charlie", "eth_nonce": 1, "pq_nonce": 4}
                ],
                "removal_change_eth": [
                    {"actor": "bob", "removal_type": "change_eth", "eth_nonce": 1, "pq_nonce": 2, "target_pq_fingerprint": "alice"}
                ]
            }
        },
        {
            "name": "test6_multiple_registration_attempts_alice_pq_switches_targets",
            "config": {
                "registration_intent": [
                    {"actor": "alice", "eth_nonce": 0, "pq_nonce": 0},
                    {"pq_actor": "alice", "eth_actor": "bob", "eth_nonce": 0, "pq_nonce": 1},
                    {"pq_actor": "alice", "eth_actor": "charlie", "eth_nonce": 0, "pq_nonce": 3}
                ],
                "removal_registration_pq": [
                    {"actor": "alice", "eth_nonce": 0, "pq_nonce": 2}
                ],
                "registration_confirmation": [
                    {"eth_actor": "charlie", "target_eth_actor": "charlie", "eth_nonce": 1, "pq_nonce": 4, "pq_actor": "alice"}
                ]
            }
        },
        {
            "name": "test7_multiple_change_attempts",
            "config": {
                "registration_intent": {"actor": "alice", "eth_nonce": 0, "pq_nonce": 0},
                "registration_confirmation": {"actor": "alice", "eth_nonce": 1, "pq_nonce": 1},
                "change_eth_address_intent": [
                    {"actor": "alice", "new_eth_address": "bob", "eth_nonce": 0, "pq_nonce": 2},
                    {"actor": "alice", "new_eth_address": "charlie", "eth_nonce": 0, "pq_nonce": 3},
                    {"actor": "alice", "new_eth_address": "danielle", "eth_nonce": 0, "pq_nonce": 5}
                ],
                "change_eth_address_confirmation": [
                    {"actor": "alice", "new_eth_address": "danielle", "eth_nonce": 1, "pq_nonce": 6}
                ],
                "removal_change_eth": [
                    {"actor": "bob", "removal_type": "change_eth", "eth_nonce": 1, "pq_nonce": 3, "target_pq_fingerprint": "alice"}
                ],
                "removal_change_pq": [
                    {"actor": "alice", "removal_type": "change_pq", "eth_nonce": 0, "pq_nonce": 4}
                ]
            }
        },
        {
            "name": "test8_unregister_revoke_unregister_confirm",
            "config": {
                "registration_intent": {"actor": "alice", "eth_nonce": 0, "pq_nonce": 0},
                "registration_confirmation": {"actor": "alice", "eth_nonce": 1, "pq_nonce": 1},
                "unregistration_intent": [
                    {"actor": "alice", "eth_actor": "alice", "eth_nonce": 2, "pq_nonce": 2},
                    {"actor": "alice", "eth_actor": "alice", "eth_nonce": 3, "pq_nonce": 4}
                ],
                "unregistration_confirmation": [
                    {"actor": "alice", "eth_actor": "alice", "eth_nonce": 4, "pq_nonce": 5}
                ],
                "removal_unregistration": [
                    {"actor": "alice", "eth_nonce": 3, "pq_nonce": 3}
                ]
            }
        },
        {
            "name": "test9_full_lifecycle",
            "config": {
                "registration_intent": {"actor": "alice", "eth_nonce": 0, "pq_nonce": 0},
                "registration_confirmation": {"actor": "alice", "eth_nonce": 1, "pq_nonce": 1},
                "change_eth_address_intent": [
                    {"actor": "alice", "new_eth_address": "bob", "eth_nonce": 0, "pq_nonce": 2}
                ],
                "change_eth_address_confirmation": [
                    {"actor": "alice", "new_eth_address": "bob", "eth_nonce": 1, "pq_nonce": 3}
                ],
                "unregistration_intent": [
                    {"pq_actor": "alice", "eth_actor": "bob", "eth_nonce": 2, "pq_nonce": 4}
                ],
                "unregistration_confirmation": [
                    {"pq_actor": "alice", "eth_actor": "bob", "eth_nonce": 3, "pq_nonce": 5}
                ],
                "final_registration_intent": [
                    {"pq_actor": "bob", "eth_actor": "alice", "eth_nonce": 2, "pq_nonce": 0}
                ],
                "final_registration_confirmation": [
                    {"pq_actor": "bob", "eth_actor": "alice", "eth_nonce": 3, "pq_nonce": 1}
                ]
            }
        }
    ]
    
    # Generate vectors for each scenario
    for scenario in scenarios:
        print(f"Generating vectors for scenario: {scenario['name']}")
        vectors = generator.generate_scenario_vectors(scenario["name"], scenario["config"])
        
        # Save individual vector files
        for vector_type, vector_data in vectors.items():
            if vector_data:
                output_file = output_path / f"{scenario['name']}_{vector_type}_vectors.json"
                # If vector_data is a list, apply bytes_to_hex to each element
                if isinstance(vector_data, list):
                    vector_data_hex = [bytes_to_hex(v) for v in vector_data]
                else:
                    vector_data_hex = bytes_to_hex(vector_data)
                # Debug: check for bytes before dumping
                if find_bytes(vector_data_hex):
                    print(f"ERROR: Still found bytes in {output_file}")
                with open(output_file, 'w') as f:
                    json.dump({vector_type: vector_data_hex}, f, indent=2)
                print(f"Saved {vector_type} vectors to: {output_file}")
        
        # Save combined scenario file with special handling for test1 and test2
        combined_file = output_path / f"{scenario['name']}_vectors.json"
        vectors_hex = {k: ([bytes_to_hex(v) for v in vlist] if isinstance(vlist, list) else bytes_to_hex(vlist)) for k, vlist in vectors.items()}
        
        # Special handling for test1 and test2 to create the expected key names
        if scenario['name'] == 'test1_eth_retry':
            # Create the specific keys expected by the test
            test1_vectors = {}
            # Generate the second registration intent (ETH nonce 1, PQ nonce 2)
            second_intent = generator.generate_registration_intent_vector("alice", 1, 2)
            test1_vectors['registration_intent_nonce2'] = [bytes_to_hex(second_intent)]
            # Generate the confirmation (ETH nonce 2, PQ nonce 3)
            confirmation = generator.generate_registration_confirmation_vector("alice", 2, 3)
            test1_vectors['registration_confirmation_nonce3'] = [bytes_to_hex(confirmation)]
            vectors_hex = test1_vectors
        elif scenario['name'] == 'test2_pq_retry':
            # Create the specific keys expected by the test
            test2_vectors = {}
            if 'registration_intent' in vectors_hex and vectors_hex['registration_intent']:
                # The second registration intent (nonce 2, pq nonce 1) should be in registration_intent_nonce2_pq1
                test2_vectors['registration_intent_nonce2_pq1'] = vectors_hex['registration_intent']
            if 'registration_confirmation' in vectors_hex and vectors_hex['registration_confirmation']:
                # The second confirmation (nonce 2, pq nonce 2) should be in registration_confirmation_nonce2_pq2
                test2_vectors['registration_confirmation_nonce2_pq2'] = vectors_hex['registration_confirmation']
            vectors_hex = test2_vectors
        
        if find_bytes(vectors_hex):
            print(f"ERROR: Still found bytes in {combined_file}")
        with open(combined_file, 'w') as f:
            json.dump(vectors_hex, f, indent=2)
        print(f"Saved combined scenario vectors to: {combined_file}")
    
    # Generate the specific vector for PQ registration with ETH removal and retry test
    print("Generating pq_registration_eth_removal_retry_vector...")
    bob_confirmation_vector = generator.generate_bob_confirmation_vector()
    bob_confirmation_vector_hex = bytes_to_hex(bob_confirmation_vector)
    if find_bytes(bob_confirmation_vector_hex):
        print("ERROR: Still found bytes in pq_registration_eth_removal_retry_vector.json")
    output_file = output_path / "pq_registration_eth_removal_retry_vector.json"
    with open(output_file, 'w') as f:
        json.dump({"pq_registration_eth_removal_retry_vector": [bob_confirmation_vector_hex]}, f, indent=2)
    print(f"Saved pq_registration_eth_removal_retry_vector to: {output_file}")
    
    # Copy test1 and test2 files to root directory where tests expect them
    print("Copying test1 and test2 files to root directory...")
    root_output_path = Path(__file__).resolve().parents[4] / "test" / "test_vectors"
    
    # Copy test1_eth_retry_vectors.json
    test1_source = output_path / "test1_eth_retry_vectors.json"
    test1_dest = root_output_path / "test1_eth_retry_vectors.json"
    if test1_source.exists():
        import shutil
        shutil.copy2(test1_source, test1_dest)
        print(f"Copied {test1_source} to {test1_dest}")
    else:
        print(f"Warning: {test1_source} not found")
    
    # Copy test2_pq_retry_vectors.json
    test2_source = output_path / "test2_pq_retry_vectors.json"
    test2_dest = root_output_path / "test2_pq_retry_vectors.json"
    if test2_source.exists():
        import shutil
        shutil.copy2(test2_source, test2_dest)
        print(f"Copied {test2_source} to {test2_dest}")
    else:
        print(f"Warning: {test2_source} not found")
    
    print("\nConsolidated advanced vector generation complete!")

if __name__ == "__main__":
    main() 
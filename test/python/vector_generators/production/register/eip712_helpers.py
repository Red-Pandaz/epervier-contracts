#!/usr/bin/env python3
"""
EIP712 Helper Functions for Vector Generators
This module provides helper functions for creating EIP712 structured signatures
"""

import hashlib
import struct
from typing import List, Dict, Any
from eth_account import Account
from eth_utils import keccak
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[3]))
from production_eip712_config import *

def keccak256(data: bytes) -> bytes:
    """Compute keccak256 hash of data"""
    return keccak(data)

def encode_packed(*args) -> bytes:
    """Encode packed data (equivalent to abi.encodePacked)"""
    result = b''
    for arg in args:
        if isinstance(arg, bytes):
            result += arg
        elif isinstance(arg, str):
            result += arg.encode('utf-8')
        elif isinstance(arg, int):
            result += arg.to_bytes(32, 'big')
        else:
            raise ValueError(f"Unsupported type: {type(arg)}")
    return result

def encode_structured_data(data: Dict[str, Any]) -> bytes:
    """Encode structured data according to EIP712"""
    # This is a simplified implementation for our specific use case
    # We'll encode the primary type directly
    primary_type = data["primaryType"]
    types = data["types"]
    message = data["message"]
    
    # Encode the struct data based on the primary type
    if primary_type == "RegistrationIntent":
        return encode_registration_intent_data(message)
    elif primary_type == "RegistrationConfirmation":
        return encode_registration_confirmation_data(message)
    elif primary_type == "RemoveIntent":
        return encode_remove_intent_data(message)
    elif primary_type == "ChangeETHAddressIntent":
        return encode_change_eth_address_intent_data(message)
    elif primary_type == "ChangeETHAddressConfirmation":
        return encode_change_eth_address_confirmation_data(message)
    elif primary_type == "UnregistrationIntent":
        return encode_unregistration_intent_data(message)
    elif primary_type == "UnregistrationConfirmation":
        return encode_unregistration_confirmation_data(message)
    elif primary_type == "RemoveChangeIntent":
        return encode_remove_change_intent_data(message)
    else:
        raise ValueError(f"Unsupported primary type: {primary_type}")

def encode_registration_intent_data(message: Dict[str, Any]) -> bytes:
    """Encode RegistrationIntent data"""
    salt = bytes.fromhex(message["salt"])
    cs1 = message["cs1"]
    cs2 = message["cs2"]
    hint = message["hint"]
    base_pq_message = bytes.fromhex(message["basePQMessage"])
    eth_nonce = message["ethNonce"]
    
    # Encode each field in the new order: salt, cs1, cs2, hint, base_pq_message, eth_nonce
    encoded = (
        salt +
        encode_packed(*[x.to_bytes(32, 'big') for x in cs1]) +
        encode_packed(*[x.to_bytes(32, 'big') for x in cs2]) +
        hint.to_bytes(32, 'big') +
        base_pq_message +
        eth_nonce.to_bytes(32, 'big')
    )
    return encoded

def encode_registration_confirmation_data(message: Dict[str, Any]) -> bytes:
    """Encode RegistrationConfirmation data (EIP-712 compliant)"""
    from eth_abi import encode
    pq_fingerprint = message["pqFingerprint"]  # hex string, e.g. '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
    eth_nonce = message["ethNonce"]
    type_hash = bytes.fromhex(REGISTRATION_CONFIRMATION_TYPE_HASH[2:])  # Remove '0x' prefix
    # EIP-712: keccak256(abi.encode(typeHash, pqFingerprint, ethNonce))
    encoded = encode(['bytes32', 'address', 'uint256'], [type_hash, pq_fingerprint, eth_nonce])
    return encoded

def encode_remove_intent_data(message: Dict[str, Any]) -> bytes:
    """Encode RemoveIntent data"""
    from eth_utils import to_checksum_address
    from eth_abi import encode
    pq_fingerprint_checksum = to_checksum_address(message["pqFingerprint"])
    eth_nonce = message["ethNonce"]
    encoded = encode([
        'address',
        'uint256'
    ], [
        pq_fingerprint_checksum,
        eth_nonce
    ])
    return encoded

def encode_change_eth_address_intent_data(message: Dict[str, Any]) -> bytes:
    """Encode ChangeETHAddressIntent data"""
    new_eth_address = int(message["newETHAddress"], 16)
    eth_nonce = message["ethNonce"]
    
    return new_eth_address.to_bytes(32, 'big') + eth_nonce.to_bytes(32, 'big')

def encode_change_eth_address_confirmation_data(message: Dict[str, Any]) -> bytes:
    """Encode ChangeETHAddressConfirmation data"""
    old_eth_address = int(message["oldETHAddress"], 16)
    eth_nonce = message["ethNonce"]
    
    return old_eth_address.to_bytes(32, 'big') + eth_nonce.to_bytes(32, 'big')

def encode_unregistration_intent_data(message: Dict[str, Any]) -> bytes:
    """Encode UnregistrationIntent data"""
    eth_nonce = message["ethNonce"]
    return eth_nonce.to_bytes(32, 'big')

def encode_unregistration_confirmation_data(message: Dict[str, Any]) -> bytes:
    """Encode UnregistrationConfirmation data"""
    pq_fingerprint = int(message["pqFingerprint"], 16)
    eth_nonce = message["ethNonce"]
    
    return pq_fingerprint.to_bytes(32, 'big') + eth_nonce.to_bytes(32, 'big')

def encode_remove_change_intent_data(message: Dict[str, Any]) -> bytes:
    """Encode RemoveChangeIntent data"""
    eth_nonce = message["ethNonce"]
    return eth_nonce.to_bytes(32, 'big')

def get_domain_separator(contract_address: str) -> bytes:
    """Compute the EIP712 domain separator"""
    # Use the hardcoded domain separator from config
    return bytes.fromhex(DOMAIN_SEPARATOR[2:])

def get_eip712_digest(domain_separator: bytes, struct_hash: bytes) -> bytes:
    """Compute the EIP712 digest"""
    from eth_utils import keccak
    packed = encode_packed(b'\x19\x01', domain_separator, struct_hash)
    print(f"DEBUG: Python packed bytes: {packed.hex()}")
    print(f"DEBUG: Python packed bytes length: {len(packed)}")
    print(f"DEBUG: Python domain_separator: {domain_separator.hex()}")
    print(f"DEBUG: Python struct_hash: {struct_hash.hex()}")
    result = keccak(packed)
    print(f"DEBUG: Python digest result: {result.hex()}")
    return result

def get_registration_intent_struct_hash(
    salt: bytes,
    cs1: List[int],
    cs2: List[int],
    hint: int,
    base_pq_message: bytes,
    eth_nonce: int
) -> bytes:
    """Compute the struct hash for RegistrationIntent"""
    struct_data = encode_structured_data({
        "types": {
            "RegistrationIntent": [
                {"name": "salt", "type": "bytes"},
                {"name": "cs1", "type": "uint256[32]"},
                {"name": "cs2", "type": "uint256[32]"},
                {"name": "hint", "type": "uint256"},
                {"name": "basePQMessage", "type": "bytes"},
                {"name": "ethNonce", "type": "uint256"}
            ]
        },
        "primaryType": "RegistrationIntent",
        "message": {
            "salt": salt.hex(),
            "cs1": cs1,
            "cs2": cs2,
            "hint": hint,
            "basePQMessage": base_pq_message.hex(),
            "ethNonce": eth_nonce
        }
    })
    
    return keccak256(struct_data)

def get_registration_confirmation_struct_hash(pq_fingerprint, eth_nonce):
    """
    Compute the struct hash for RegistrationConfirmation(address pqFingerprint,uint256 ethNonce)
    """
    from eth_utils import keccak, to_checksum_address
    from eth_abi import encode
    type_hash = bytes.fromhex("18de7768ef44f4d9fc06fe05870b6e013cdefc55ac93a9ba5ecc3bcdbe73c57f")
    pq_fingerprint_checksum = to_checksum_address(pq_fingerprint)
    encoded = encode([
        'bytes32',
        'address',
        'uint256'
    ], [
        type_hash,
        pq_fingerprint_checksum,
        eth_nonce
    ])
    return keccak(encoded)

def get_remove_intent_struct_hash(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Compute the struct hash for RemoveIntent(address pqFingerprint,uint256 ethNonce)"""
    from eth_utils import keccak, to_checksum_address
    from eth_abi import encode
    type_hash = bytes.fromhex(REMOVE_INTENT_TYPE_HASH[2:])  # Remove '0x' prefix
    pq_fingerprint_checksum = to_checksum_address(pq_fingerprint)
    encoded = encode([
        'bytes32',
        'address',
        'uint256'
    ], [
        type_hash,
        pq_fingerprint_checksum,
        eth_nonce
    ])
    return keccak(encoded)

def get_change_eth_address_intent_struct_hash(new_eth_address: str, pq_fingerprint: str, eth_nonce: int) -> bytes:
    """
    Compute the struct hash for ChangeETHAddressIntent(address newETHAddress,address pqFingerprint,uint256 ethNonce)
    Using abi.encode like the contract implementation
    """
    from eth_utils import keccak, to_checksum_address
    from eth_abi import encode
    
    type_hash = bytes.fromhex(CHANGE_ETH_ADDRESS_INTENT_TYPE_HASH[2:])
    
    # Convert hex strings to checksum addresses for proper encoding
    new_eth_address_checksum = to_checksum_address(new_eth_address)
    pq_fingerprint_checksum = to_checksum_address(pq_fingerprint)
    
    print(f"DEBUG: type_hash: {type_hash.hex()}")
    print(f"DEBUG: new_eth_address: {new_eth_address}")
    print(f"DEBUG: new_eth_address_checksum: {new_eth_address_checksum}")
    print(f"DEBUG: pq_fingerprint: {pq_fingerprint}")
    print(f"DEBUG: pq_fingerprint_checksum: {pq_fingerprint_checksum}")
    print(f"DEBUG: eth_nonce: {eth_nonce}")
    
    # Use abi.encode like the contract implementation
    encoded_data = encode([
        'bytes32',
        'address',
        'address',
        'uint256'
    ], [
        type_hash,
        new_eth_address_checksum,
        pq_fingerprint_checksum,
        eth_nonce
    ])
    
    print(f"DEBUG: encoded_data: {encoded_data.hex()}")
    
    struct_hash = keccak(encoded_data)
    print(f"DEBUG: PYTHON struct_hash: {struct_hash.hex()}")
    
    return struct_hash

def get_change_eth_address_confirmation_struct_hash(old_eth_address: str, pq_fingerprint: str, base_pq_message: bytes, salt: bytes, cs1: List[int], cs2: List[int], hint: int, eth_nonce: int) -> bytes:
    """Compute the struct hash for ChangeETHAddressConfirmation(address oldETHAddress,address pqFingerprint,bytes basePQMessage,bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,uint256 ethNonce)"""
    from eth_utils import keccak, to_checksum_address
    from eth_abi import encode
    type_hash = bytes.fromhex(CHANGE_ETH_ADDRESS_CONFIRMATION_TYPE_HASH[2:])  # Remove '0x' prefix
    old_eth_address_checksum = to_checksum_address(old_eth_address)
    pq_fingerprint_checksum = to_checksum_address(pq_fingerprint)
    print(f"DEBUG: type_hash: {type_hash.hex()}")
    print(f"DEBUG: old_eth_address: {old_eth_address}")
    print(f"DEBUG: old_eth_address_checksum: {old_eth_address_checksum}")
    print(f"DEBUG: pq_fingerprint: {pq_fingerprint}")
    print(f"DEBUG: pq_fingerprint_checksum: {pq_fingerprint_checksum}")
    print(f"DEBUG: eth_nonce: {eth_nonce}")
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
    print(f"DEBUG: encoded_data: {encoded_data.hex()}")
    struct_hash = keccak(encoded_data)
    print(f"DEBUG: struct_hash: {struct_hash.hex()}")
    return struct_hash

def get_unregistration_intent_struct_hash(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """
    Compute the struct hash for UnregistrationIntent(address pqFingerprint,uint256 ethNonce)
    Using abi.encode like the contract implementation
    """
    from eth_utils import keccak, to_checksum_address
    from eth_abi import encode
    
    type_hash = bytes.fromhex(UNREGISTRATION_INTENT_TYPE_HASH[2:])
    pq_fingerprint_checksum = to_checksum_address(pq_fingerprint)
    
    print(f"DEBUG: type_hash: {type_hash.hex()}")
    print(f"DEBUG: pq_fingerprint: {pq_fingerprint}")
    print(f"DEBUG: pq_fingerprint_checksum: {pq_fingerprint_checksum}")
    print(f"DEBUG: eth_nonce: {eth_nonce}")
    
    # Use abi.encode like the contract implementation
    encoded_data = encode(['bytes32', 'address', 'uint256'], [type_hash, pq_fingerprint_checksum, eth_nonce])
    
    print(f"DEBUG: encoded_data: {encoded_data.hex()}")
    
    struct_hash = keccak(encoded_data)
    print(f"DEBUG: struct_hash: {struct_hash.hex()}")
    
    return struct_hash

def get_unregistration_confirmation_struct_hash(pq_fingerprint: str, base_pq_message: bytes, salt: bytes, cs1: List[int], cs2: List[int], hint: int, eth_nonce: int) -> bytes:
    """Compute the struct hash for UnregistrationConfirmation(address pqFingerprint,bytes basePQMessage,bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,uint256 ethNonce)"""
    from eth_utils import keccak, to_checksum_address
    from eth_abi import encode
    type_hash = bytes.fromhex(UNREGISTRATION_CONFIRMATION_TYPE_HASH[2:])  # Remove '0x' prefix
    pq_fingerprint_checksum = to_checksum_address(pq_fingerprint)
    print(f"DEBUG: type_hash: {type_hash.hex()}")
    print(f"DEBUG: pq_fingerprint: {pq_fingerprint}")
    print(f"DEBUG: pq_fingerprint_checksum: {pq_fingerprint_checksum}")
    print(f"DEBUG: eth_nonce: {eth_nonce}")
    # Use abi.encode like the contract implementation
    encoded_data = encode([
        'bytes32',
        'address',
        'bytes32',  # keccak256(basePQMessage)
        'bytes32',  # keccak256(salt)
        'bytes32',  # keccak256(abi.encodePacked(cs1))
        'bytes32',  # keccak256(abi.encodePacked(cs2))
        'uint256',
        'uint256'
    ], [
        type_hash,
        pq_fingerprint_checksum,
        keccak(base_pq_message),
        keccak(salt),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs1])),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs2])),
        hint,
        eth_nonce
    ])
    print(f"DEBUG: encoded_data: {encoded_data.hex()}")
    struct_hash = keccak(encoded_data)
    print(f"DEBUG: struct_hash: {struct_hash.hex()}")
    return struct_hash

def get_remove_change_intent_struct_hash(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """
    Compute the struct hash for RemoveChangeIntent(address pqFingerprint,uint256 ethNonce)
    Using abi.encode like the contract implementation
    """
    from eth_utils import keccak, to_checksum_address
    from eth_abi import encode
    
    type_hash = bytes.fromhex(REMOVE_CHANGE_INTENT_TYPE_HASH[2:])
    pq_fingerprint_checksum = to_checksum_address(pq_fingerprint)
    
    print(f"DEBUG: type_hash: {type_hash.hex()}")
    print(f"DEBUG: pq_fingerprint: {pq_fingerprint}")
    print(f"DEBUG: pq_fingerprint_checksum: {pq_fingerprint_checksum}")
    print(f"DEBUG: eth_nonce: {eth_nonce}")
    
    # Use abi.encode like the contract: abi.encode(REMOVE_CHANGE_INTENT_TYPE_HASH, pqFingerprint, ethNonce)
    encoded_data = encode(['bytes32', 'address', 'uint256'], [type_hash, pq_fingerprint_checksum, eth_nonce])
    
    print(f"DEBUG: encoded_data: {encoded_data.hex()}")
    
    struct_hash = keccak(encoded_data)
    print(f"DEBUG: struct_hash: {struct_hash.hex()}")
    
    return struct_hash

def sign_eip712_message(digest: bytes, private_key: str) -> dict:
    """
    Sign an EIP-712 digest using the same pattern as the working registration intent generator
    """
    from eth_account import Account
    
    # Convert private key from hex string to bytes
    if private_key.startswith('0x'):
        private_key = private_key[2:]
    private_key_bytes = bytes.fromhex(private_key)
    
    # Sign the digest using the same pattern as registration intent
    account = Account.from_key(private_key_bytes)
    sig = Account._sign_hash(digest, private_key=account.key)
    
    return {
        "v": sig.v,
        "r": sig.r,
        "s": sig.s
    }

def get_dynamic_domain_separator(contract_address: str) -> bytes:
    """
    Compute the domain separator dynamically like the contract does
    This matches the contract's constructor logic
    """
    from eth_utils import keccak
    
    # EIP-712 domain separator computation
    # keccak256(abi.encode(
    #     keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    #     keccak256(bytes(DOMAIN_NAME)),
    #     keccak256(bytes(DOMAIN_VERSION)),
    #     11155420, // Optimism Sepolia chain ID
    #     address(this)
    # ))
    
    # EIP-712 domain type hash
    domain_type_hash = keccak(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    
    # Domain name and version
    domain_name_hash = keccak(b"PQRegistry")
    domain_version_hash = keccak(b"1")
    
    # Chain ID (Optimism Sepolia)
    chain_id = 11155420
    
    # Contract address (remove 0x prefix and convert to bytes)
    contract_address_bytes = bytes.fromhex(contract_address[2:])
    
    # Encode the domain separator
    from eth_abi import encode
    encoded_domain = encode(
        ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
        [domain_type_hash, domain_name_hash, domain_version_hash, chain_id, contract_address_bytes]
    )
    
    domain_separator = keccak(encoded_domain)
    return domain_separator 
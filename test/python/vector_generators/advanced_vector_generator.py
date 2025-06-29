#!/usr/bin/env python3
"""
Advanced Vector Generator for PQRegistry Testing

This generator can create test vectors with custom nonces for advanced testing scenarios.
It extends the basic generator to support:
- Custom nonce values
- Multiple actors with different nonces
- Complex state transition scenarios
"""

import json
import os
import sys
from typing import Dict, List, Any, Optional
from web3 import Web3
from eth_account import Account
import secrets
from pathlib import Path
from eth_utils import decode_hex, keccak
from eth_account.messages import encode_defunct
import hashlib
import hmac

# Add the parent directory to the path to import the basic generator
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Define constants and helper functions
PROJECT_ROOT = Path(__file__).resolve().parents[3]  # epervier-registry
ACTORS_CONFIG_PATH = PROJECT_ROOT / "test/test_keys/actors_config.json"
DOMAIN_SEPARATOR = Web3.keccak(b"PQRegistry")
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADVANCED_VECTOR_DIR = os.path.join(os.path.dirname(__file__), '../../test_vectors/advanced')

def load_actors_config():
    """Load the actors config JSON"""
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]

def generate_epervier_signature(message: bytes, actor: str) -> Dict[str, Any]:
    """Generate Epervier signature for a message"""
    import subprocess
    
    actors = load_actors_config()
    actor_data = actors[actor]
    pq_private_key_file = actor_data["pq_private_key_file"]
    
    sign_cli = PROJECT_ROOT / "ETHFALCON/python-ref/sign_cli.py"
    privkey_path = PROJECT_ROOT / "test/test_keys" / pq_private_key_file
    venv_python = PROJECT_ROOT / "ETHFALCON/python-ref/myenv/bin/python3"
    
    cmd = [
        str(venv_python), str(sign_cli), "sign",
        f"--privkey={privkey_path}",
        f"--data={message.hex()}",
        "--version=epervier"
    ]
    
    # Add retry logic with a maximum number of attempts
    max_retries = 10
    for attempt in range(max_retries):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)  # 30 second timeout
            if result.returncode != 0:
                print(f"Error signing message (attempt {attempt + 1}/{max_retries}): {result.stderr}")
                if attempt == max_retries - 1:
                    print(f"Failed to generate signature after {max_retries} attempts")
                    return None
                continue
            
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
                print(f"Failed to parse signature components (attempt {attempt + 1}/{max_retries})")
                if attempt == max_retries - 1:
                    return None
                continue
            
            # If we get here, we have a valid signature
            return {
                "salt": signature_data["salt"],
                "hint": signature_data["hint"],
                "cs1": signature_data["cs1"],
                "cs2": signature_data["cs2"]
            }
            
        except subprocess.TimeoutExpired:
            print(f"Signature generation timed out (attempt {attempt + 1}/{max_retries})")
            if attempt == max_retries - 1:
                print("Failed to generate signature due to timeout")
                return None
        except Exception as e:
            print(f"Unexpected error during signature generation (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt == max_retries - 1:
                return None
    
    return None

def generate_eth_signature(message: bytes, private_key: str) -> Dict[str, Any]:
    """Generate ETH signature for a message"""
    from eth_account.messages import encode_defunct
    
    account = Account.from_key(private_key)
    message_hash = encode_defunct(message)
    signed_message = account.sign_message(message_hash)
    
    return {
        "v": signed_message.v,
        "r": hex(signed_message.r),  # Convert to hex string
        "s": hex(signed_message.s),  # Convert to hex string
        "signature": signed_message.signature.hex()
    }

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

# Message creation functions based on the schema
def create_base_pq_registration_intent_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create base PQ registration intent message according to schema - matching working generator format"""
    # BasePQRegistrationIntentMessage: DOMAIN_SEPARATOR + pattern + ethAddress + pqNonce
    # Use exact same format as working generator
    pattern = b"Intent to pair ETH Address "  # bytes, not string
    return DOMAIN_SEPARATOR + pattern + bytes.fromhex(eth_address[2:]) + pq_nonce.to_bytes(32, 'big')

def create_eth_registration_intent_message(base_pq_message: bytes, salt: bytes, cs1: List[int], cs2: List[int], hint: int, eth_nonce: int) -> bytes:
    """Create ETH registration intent message according to schema - matching working generator format"""
    # ETHRegistrationIntentMessage: DOMAIN_SEPARATOR + pattern + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
    # Use exact same format as working generator
    pattern = b"Intent to pair Epervier Key"  # bytes, not string
    
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    
    return (
        DOMAIN_SEPARATOR + pattern + base_pq_message + salt +
        pack_uint256_array(cs1) + pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') + eth_nonce.to_bytes(32, 'big')
    )

def create_base_eth_registration_confirmation_message(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Create base ETH registration confirmation message according to schema"""
    # BaseETHRegistrationConfirmationMessage: DOMAIN_SEPARATOR + pattern + pqFingerprint + ethNonce
    pattern = b"Confirm bonding to Epervier Fingerprint "
    
    # Manual concatenation to ensure correct format
    message = (
        DOMAIN_SEPARATOR +
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix, convert to raw bytes
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def create_pq_registration_confirmation_message(eth_address: str, base_eth_message: bytes, v: int, r: str, s: str, pq_nonce: int) -> bytes:
    """Create PQ registration confirmation message according to schema"""
    # PQRegistrationConfirmationMessage: DOMAIN_SEPARATOR + pattern + ethAddress + baseETHMessage + v + r + s + pqNonce
    pattern = b"Confirm bonding to ETH Address "  # Correct pattern matching MessageParser.sol
    
    # Manual concatenation to ensure correct format
    message = (
        DOMAIN_SEPARATOR +
        pattern +
        bytes.fromhex(eth_address[2:]) +  # Remove "0x" prefix, convert to raw bytes
        base_eth_message +
        v.to_bytes(1, 'big') +
        int(r, 16).to_bytes(32, 'big') +  # Convert hex string to bytes
        int(s, 16).to_bytes(32, 'big') +  # Convert hex string to bytes
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_base_eth_change_eth_address_intent_message(pq_fingerprint: str, new_eth_address: str, eth_nonce: int) -> bytes:
    """Create base ETH change address intent message according to working vector schema"""
    pattern = b"Intent to change ETH Address and bond with Epervier Fingerprint "
    pattern2 = b" to "
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Raw 20-byte address
    new_eth_address_bytes = bytes.fromhex(new_eth_address[2:])  # Raw 20-byte address
    eth_nonce_bytes = eth_nonce.to_bytes(32, 'big')

    print(f"DEBUG: pattern length: {len(pattern)} value: {pattern}")
    print(f"DEBUG: pattern hex: {pattern.hex()}")
    print(f"DEBUG: pattern as string: '{pattern.decode()}'")
    print(f"DEBUG: pq_fingerprint length: {len(pq_fingerprint_bytes)} value: {pq_fingerprint_bytes.hex()}")
    print(f"DEBUG: pattern2 length: {len(pattern2)} value: {pattern2}")
    print(f"DEBUG: new_eth_address length: {len(new_eth_address_bytes)} value: {new_eth_address_bytes.hex()}")
    print(f"DEBUG: eth_nonce length: {len(eth_nonce_bytes)} value: {eth_nonce_bytes.hex()}")

    base_message = (
        DOMAIN_SEPARATOR +  # Include domain separator like working generator
        pattern +
        pq_fingerprint_bytes +
        pattern2 +
        new_eth_address_bytes +
        eth_nonce_bytes
    )

    print(f"DEBUG: base_message before pad/trunc length: {len(base_message)} value: {base_message}")
    print(f"DEBUG: base_message hex: {base_message.hex()}")

    if len(base_message) > 172:
        base_message = base_message[:172]
    elif len(base_message) < 172:
        base_message = base_message + b'\x00' * (172 - len(base_message))

    print(f"DEBUG: base_message final length: {len(base_message)} value: {base_message}")
    print(f"DEBUG: base_message final hex: {base_message.hex()}")
    return base_message

def create_pq_change_eth_address_intent_message(old_eth_address: str, new_eth_address: str, base_eth_message: bytes, v: int, r: str, s: str, pq_nonce: int) -> bytes:
    """Create PQ change address intent message according to working vector schema"""
    pattern = b"Intent to change bound ETH Address from "
    pattern2 = b" to "
    message = DOMAIN_SEPARATOR
    message += pattern
    message += bytes.fromhex(old_eth_address[2:])
    message += pattern2
    message += bytes.fromhex(new_eth_address[2:])
    message += base_eth_message
    message += v.to_bytes(1, 'big')
    # Format r and s as int(hex, 16).to_bytes(32, 'big')
    r_bytes = int(r, 16).to_bytes(32, 'big')
    s_bytes = int(s, 16).to_bytes(32, 'big')
    message += r_bytes
    message += s_bytes
    message += pq_nonce.to_bytes(32, 'big')
    print(f"DEBUG: Final PQ message length: {len(message)} bytes (should be ~385)")
    print(f"DEBUG: First 200 bytes: {message[:200].hex()}")
    return message

def create_base_pq_change_eth_address_confirm_message(old_eth_address: str, new_eth_address: str, pq_nonce: int) -> bytes:
    """Create base PQ change address confirmation message according to schema"""
    # BasePQChangeETHAddressConfirmMessage: DOMAIN_SEPARATOR + pattern + oldEthAddress + pattern2 + newEthAddress + pqNonce
    pattern = b"Confirm changing bound ETH Address for Epervier Fingerprint from "
    pattern2 = b" to "
    
    # Manual concatenation to ensure exact byte structure (173 bytes total)
    message = (
        DOMAIN_SEPARATOR +
        pattern +
        bytes.fromhex(old_eth_address[2:]) +  # Remove "0x" prefix, 20 bytes
        pattern2 +
        bytes.fromhex(new_eth_address[2:]) +  # Remove "0x" prefix, 20 bytes
        pq_nonce.to_bytes(32, 'big')  # 32 bytes
    )
    return message

def create_eth_change_eth_address_confirmation_message(pq_fingerprint: str, base_pq_message: bytes, salt: bytes, cs1: List[int], cs2: List[int], hint: int, eth_nonce: int) -> bytes:
    """Create ETH change address confirmation message according to schema (manual byte concatenation)"""
    pattern = b"Confirm change ETH Address for Epervier Fingerprint "
    
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    
    message = (
        DOMAIN_SEPARATOR +  # 32 bytes
        pattern +  # 52 bytes
        bytes.fromhex(pq_fingerprint[2:]) +  # 20 bytes
        base_pq_message +  # 173 bytes
        salt +  # 40 bytes
        pack_uint256_array(cs1) +  # 1024 bytes
        pack_uint256_array(cs2) +  # 1024 bytes
        hint.to_bytes(32, 'big') +  # 32 bytes
        eth_nonce.to_bytes(32, 'big')  # 32 bytes
    )
    print(f"DEBUG: Final message length: {len(message)} (should be 2429)")
    return message

def create_base_eth_unregistration_intent_message(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Create base ETH unregistration intent message according to schema"""
    # BaseETHUnregistrationIntentMessage: pattern + pqFingerprint + ethNonce
    pattern = "Intent to unregister from Epervier Fingerprint "
    return abi_encode_packed(
        pattern,
        pq_fingerprint,
        eth_nonce
    )

def create_pq_unregistration_intent_message(eth_address: str, base_eth_message: bytes, v: int, r: bytes, s: bytes, pq_nonce: int) -> bytes:
    """Create PQ unregistration intent message according to schema"""
    # PQUnregistrationIntentMessage: DOMAIN_SEPARATOR + pattern + currentEthAddress + baseETHMessage + v + r + s + pqNonce
    pattern = "Intent to unregister from Epervier Fingerprint from address "
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        pattern,
        eth_address,
        base_eth_message,
        v,
        r,
        s,
        pq_nonce
    )

def create_base_pq_unregistration_confirm_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create base PQ unregistration confirmation message according to schema"""
    # BasePQUnregistrationConfirmMessage: DOMAIN_SEPARATOR + pattern + ethAddress + pqNonce
    pattern = "Confirm unregistration from ETH Address "
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        pattern,
        eth_address,
        pq_nonce
    )

def create_eth_unregistration_confirmation_message(pq_fingerprint: str, base_pq_message: bytes, salt: bytes, cs1: List[int], cs2: List[int], hint: int, eth_nonce: int) -> bytes:
    """Create ETH unregistration confirmation message according to schema"""
    # ETHUnregistrationConfirmationMessage: pattern + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
    pattern = "Confirm unregistration from Epervier Fingerprint "
    return abi_encode_packed(
        pattern,
        pq_fingerprint,
        base_pq_message,
        salt,
        cs1,
        cs2,
        hint,
        eth_nonce
    )

def create_eth_remove_registration_intent_message(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Create ETH remove registration intent message according to schema"""
    # ETHRemoveRegistrationIntentMessage: pattern + pqFingerprint + ethNonce
    pattern = "Remove registration intent from Epervier Fingerprint "
    return abi_encode_packed(
        pattern,
        pq_fingerprint,
        eth_nonce
    )

def create_pq_remove_registration_intent_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create PQ remove registration intent message according to schema"""
    # PQRemoveRegistrationIntentMessage: DOMAIN_SEPARATOR + pattern + ethAddress + pqNonce
    pattern = b"Remove registration intent from ETH Address "
    
    # Manual concatenation to ensure ETH address is raw bytes, not ASCII hex string
    message = (
        DOMAIN_SEPARATOR +
        pattern +
        bytes.fromhex(eth_address[2:]) +  # Remove "0x" prefix, convert to raw bytes
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_eth_remove_change_intent_message(pq_fingerprint: str, eth_nonce: int) -> bytes:
    """Create ETH remove change intent message according to schema"""
    # ETHRemoveChangeIntentMessage: DOMAIN_SEPARATOR + pattern + pqFingerprint + ethNonce
    pattern = b"Remove change intent from Epervier Fingerprint "
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Convert hex address to bytes
    eth_nonce_bytes = eth_nonce.to_bytes(32, 'big')
    
    message = DOMAIN_SEPARATOR + pattern + pq_fingerprint_bytes + eth_nonce_bytes
    return message

def create_pq_remove_change_intent_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create PQ remove change intent message according to schema"""
    # PQRemoveChangeIntentMessage: DOMAIN_SEPARATOR + pattern + ethAddress + pqNonce
    pattern = b"Remove change intent from ETH Address "
    
    # Manual concatenation to ensure ETH address is raw bytes, not ASCII hex string
    message = (
        DOMAIN_SEPARATOR +
        pattern +
        bytes.fromhex(eth_address[2:]) +  # Remove "0x" prefix, convert to raw bytes
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_pq_remove_unregistration_intent_message(eth_address: str, pq_nonce: int) -> bytes:
    """Create PQ remove unregistration intent message according to schema"""
    # PQRemoveUnregistrationIntentMessage: DOMAIN_SEPARATOR + pattern + ethAddress + pqNonce
    pattern = b"Remove unregistration intent from ETH Address "
    
    # Manual concatenation to ensure ETH address is raw bytes, not ASCII hex string
    message = (
        DOMAIN_SEPARATOR +
        pattern +
        bytes.fromhex(eth_address[2:]) +  # Remove "0x" prefix, convert to raw bytes
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def bytes_to_hex(obj):
    """Recursively convert bytes fields to hex strings for JSON serialization."""
    if isinstance(obj, bytes):
        return obj.hex()
    elif isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if k in ["cs1", "cs2"] and isinstance(v, list):
                # Convert signature components to hex strings like working vectors
                result[k] = [f"0x{x:064x}" for x in v]
            else:
                result[k] = bytes_to_hex(v)
        return result
    elif isinstance(obj, list):
        return [bytes_to_hex(x) for x in obj]
    else:
        return obj

def find_bytes(obj, path="root"):
    """Recursively find bytes objects in a nested structure and print their paths."""
    if isinstance(obj, bytes):
        print(f"DEBUG: Found bytes at {path}")
        return True
    elif isinstance(obj, dict):
        found = False
        for k, v in obj.items():
            if find_bytes(v, f"{path}.{k}"):
                found = True
        return found
    elif isinstance(obj, list):
        found = False
        for i, v in enumerate(obj):
            if find_bytes(v, f"{path}[{i}]"):
                found = True
        return found
    return False

class AdvancedVectorGenerator:
    def __init__(self):
        self.w3 = Web3()
        self.account = Account()
        
        # Load actors from the main config
        self.actors_config = load_actors_config()
        
        # Actor configurations with their private keys and addresses
        # Use all actors from the config instead of just alice, bob, charlie
        self.actors = self.actors_config
    
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

        # Create full ETH message (domain separator + pattern + base PQ message + salt + cs1 + cs2 + hint + ethNonce)
        eth_message = create_eth_registration_intent_message(
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            eth_nonce
        )

        # Generate ETH signature
        eth_signature = generate_eth_signature(eth_message, actor_data["eth_private_key"])

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
        eth_signature = generate_eth_signature(eth_message, eth_actor_data["eth_private_key"])

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
        eth_signature = generate_eth_signature(base_eth_message, actor_data["eth_private_key"])
        
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
    
    def generate_change_eth_address_intent_vector(self, actor: str, new_eth_address: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a change ETH address intent vector with custom nonces"""
        print(f"DEBUG: generate_change_eth_address_intent_vector called with actor={actor}, new_eth_address={new_eth_address}, eth_nonce={eth_nonce}, pq_nonce={pq_nonce}")
        
        actor_data = self.actors[actor]
        
        # Handle actor name as new ETH address
        if new_eth_address in self.actors:
            new_eth_actor_data = self.actors[new_eth_address]
            resolved_new_eth_address = new_eth_actor_data["eth_address"]
            new_eth_private_key = new_eth_actor_data["eth_private_key"]
            new_actor = new_eth_address
            print(f"DEBUG: Resolved actor '{new_eth_address}' to ETH address '{resolved_new_eth_address}'")
        else:
            # Use the actor's own private key if new_eth_address is a direct address
            resolved_new_eth_address = new_eth_address
            new_eth_private_key = actor_data["eth_private_key"]
            new_actor = actor
            print(f"DEBUG: Using direct ETH address '{resolved_new_eth_address}'")
        
        print(f"DEBUG: About to call create_base_eth_change_eth_address_intent_message with pq_fingerprint={actor_data['pq_fingerprint']}, resolved_new_eth_address={resolved_new_eth_address}, eth_nonce={eth_nonce}")
        
        # Create base ETH change intent message
        base_eth_message = create_base_eth_change_eth_address_intent_message(
            actor_data["pq_fingerprint"],
            resolved_new_eth_address,  # Use resolved ETH address
            eth_nonce
        )
        
        # Generate ETH signature with the new ETH address's private key
        eth_signature = generate_eth_signature(base_eth_message, new_eth_private_key)
        
        # Create PQ change intent message
        pq_message = create_pq_change_eth_address_intent_message(
            actor_data["eth_address"],
            resolved_new_eth_address,  # Use resolved ETH address
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
            "new_eth_address": resolved_new_eth_address,  # Use resolved ETH address
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
            resolved_new_eth_address,  # Use resolved ETH address
            pq_nonce
        )
        
        # Generate PQ signature
        pq_signature = generate_epervier_signature(base_pq_message, actor)
        
        # Create ETH confirmation message
        eth_message = create_eth_change_eth_address_confirmation_message(
            actor_data["pq_fingerprint"],
            base_pq_message,
            pq_signature["salt"],
            pq_signature["cs1"],
            pq_signature["cs2"],
            pq_signature["hint"],
            eth_nonce
        )
        
        # Generate ETH signature with the new ETH address's private key
        eth_signature = generate_eth_signature(eth_message, new_eth_private_key)
        
        return {
            "current_actor": actor,
            "new_actor": new_actor,
            "old_eth_address": actor_data["eth_address"],
            "new_eth_address": resolved_new_eth_address,  # Use resolved ETH address
            "pq_fingerprint": actor_data["pq_fingerprint"],
            "base_pq_message": base_pq_message.hex(),
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "pq_signature": pq_signature,
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
        eth_signature = generate_eth_signature(base_eth_message, actor_data["eth_private_key"])
        
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
        
        # Create ETH confirmation message
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
        eth_signature = generate_eth_signature(eth_message, actor_data["eth_private_key"])
        
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
    
    def generate_removal_vector(self, actor: str, removal_type: str, eth_nonce: int, pq_nonce: int, target_pq_fingerprint: str = None) -> Dict[str, Any]:
        """Generate a removal vector with custom nonces"""
        actor_data = self.actors[actor]
        
        if removal_type == "registration_eth":
            message = create_eth_remove_registration_intent_message(
                actor_data["pq_fingerprint"],
                eth_nonce
            )
            signature = generate_eth_signature(message, actor_data["eth_private_key"])
            return {
                "actor": actor,
                "eth_address": actor_data["eth_address"],
                "pq_fingerprint": actor_data["pq_fingerprint"],
                "eth_message": message.hex(),
                "eth_signature": signature,
                "eth_nonce": eth_nonce
            }
        
        elif removal_type == "registration_pq":
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
        
        elif removal_type == "change_eth":
            # For change_eth removal, use the target PQ fingerprint (Alice's) instead of the actor's own
            pq_fingerprint = target_pq_fingerprint if target_pq_fingerprint else actor_data["pq_fingerprint"]
            message = create_eth_remove_change_intent_message(
                pq_fingerprint,
                eth_nonce
            )
            signature = generate_eth_signature(message, actor_data["eth_private_key"])
            return {
                "actor": actor,
                "eth_address": actor_data["eth_address"],
                "pq_fingerprint": pq_fingerprint,
                "eth_message": message.hex(),
                "eth_signature": signature,
                "eth_nonce": eth_nonce
            }
        
        elif removal_type == "change_pq":
            message = create_pq_remove_change_intent_message(
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
        
        elif removal_type == "unregistration_pq":
            message = create_pq_remove_unregistration_intent_message(
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
        
        else:
            raise ValueError(f"Unknown removal type: {removal_type}")
    
    def generate_scenario_vectors(self, scenario_name: str, scenario_config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate vectors for a complete test scenario"""
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
                # Handle single registration intent
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
                vectors["registration_intent"] = [vector]
        
        # Generate registration confirmation vectors
        if "registration_confirmation" in scenario_config:
            config = scenario_config["registration_confirmation"]
            if isinstance(config, list):
                # Handle multiple registration confirmations
                vectors["registration_confirmation"] = []
                for confirm_config in config:
                    if "eth_actor" in confirm_config and "target_eth_actor" in confirm_config:
                        # Cross-actor confirmation
                        vector = self.generate_cross_actor_registration_confirmation_vector(
                            confirm_config["eth_actor"],
                            confirm_config["target_eth_actor"],
                            confirm_config["eth_nonce"],
                            confirm_config["pq_nonce"]
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
                # Handle single registration confirmation
                if "eth_actor" in config and "target_eth_actor" in config:
                    # Cross-actor confirmation
                    vector = self.generate_cross_actor_registration_confirmation_vector(
                        config["eth_actor"],
                        config["target_eth_actor"],
                        config["eth_nonce"],
                        config["pq_nonce"]
                    )
                else:
                    # Standard confirmation
                    vector = self.generate_registration_confirmation_vector(
                        config["actor"], 
                        config["eth_nonce"], 
                        config["pq_nonce"]
                    )
                vectors["registration_confirmation"] = [vector]
        
        # Generate change ETH address intent vectors
        if "change_eth_address_intent" in scenario_config:
            vectors["change_eth_address_intent"] = []
            for config in scenario_config["change_eth_address_intent"]:
                vector = self.generate_change_eth_address_intent_vector(
                    config["actor"],
                    config["new_eth_address"],
                    config["eth_nonce"],
                    config["pq_nonce"]
                )
                vectors["change_eth_address_intent"].append(vector)
        
        # Generate change ETH address confirmation vectors
        if "change_eth_address_confirmation" in scenario_config:
            vectors["change_eth_address_confirmation"] = []
            for config in scenario_config["change_eth_address_confirmation"]:
                vector = self.generate_change_eth_address_confirmation_vector(
                    config["actor"],
                    config["new_eth_address"],
                    config["eth_nonce"],
                    config["pq_nonce"]
                )
                vectors["change_eth_address_confirmation"].append(vector)
        
        # Generate removal vectors
        if "removal_change_pq" in scenario_config:
            vectors["removal_change_pq"] = []
            for config in scenario_config["removal_change_pq"]:
                vector = self.generate_removal_vector(
                    config["actor"],
                    "change_pq",
                    config["eth_nonce"],
                    config["pq_nonce"]
                )
                vectors["removal_change_pq"].append(vector)
        
        if "removal_change_eth" in scenario_config:
            vectors["removal_change_eth"] = []
            for config in scenario_config["removal_change_eth"]:
                target_pq_fingerprint = None
                if "target_pq_fingerprint" in config:
                    # Get the target PQ fingerprint from the actors config
                    target_pq_fingerprint = self.actors[config["target_pq_fingerprint"]]["pq_fingerprint"]
                vector = self.generate_removal_vector(
                    config["actor"],
                    "change_eth",
                    config["eth_nonce"],
                    config["pq_nonce"],
                    target_pq_fingerprint
                )
                vectors["removal_change_eth"].append(vector)
        
        if "removal_registration_pq" in scenario_config:
            vectors["removal_registration_pq"] = []
            for config in scenario_config["removal_registration_pq"]:
                vector = self.generate_removal_vector(
                    config["actor"],
                    "registration_pq",
                    config["eth_nonce"],
                    config["pq_nonce"]
                )
                vectors["removal_registration_pq"].append(vector)
        
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
        
        # Create confirmation message with exact same format as working vectors
        # This should be 304 bytes like the working vector
        pq_message = (
            DOMAIN_SEPARATOR +
            b"Confirm bonding to ETH Address " +
            eth_address_bytes +
            DOMAIN_SEPARATOR +
            b"Confirm bonding to Epervier Fingerprint " +
            pq_fingerprint_bytes +
            eth_nonce.to_bytes(32, 'big') +
            (27).to_bytes(1, 'big') +  # Use a standard v value
            bytes.fromhex("1c412aaf01c4ee687b76415386340a7fc5ded0855c922b6ebdf32335d4e4726a") +  # Use working r value (32 bytes)
            bytes.fromhex("f13e7d6841a6d4a100bbab466e18a162bef32a4f1871ba23a6c6f38d99f486ae") +  # Use working s value (32 bytes)
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

    def generate_cross_actor_registration_confirmation_vector(self, eth_actor: str, target_eth_actor: str, eth_nonce: int, pq_nonce: int) -> Dict[str, Any]:
        """Generate a registration confirmation vector where one actor's ETH key confirms for another actor's ETH address"""
        eth_actor_data = self.actors[eth_actor]
        target_eth_actor_data = self.actors[target_eth_actor]
        
        # For cross-actor confirmation, we need to determine which PQ fingerprint to use
        # The base ETH message should contain the PQ fingerprint of the actor who has the pending registration intent
        # In this case, Alice has the pending registration intent, so we use Alice's PQ fingerprint
        alice_data = self.actors["alice"]
        
        # Create base ETH confirmation message with Alice's PQ fingerprint (the one with pending intent)
        base_eth_message = create_base_eth_registration_confirmation_message(
            alice_data["pq_fingerprint"],  # Use Alice's PQ fingerprint (the one with pending intent)
            eth_nonce
        )
        
        # Generate ETH signature using the ETH actor's key
        eth_signature = generate_eth_signature(base_eth_message, eth_actor_data["eth_private_key"])
        
        # Create PQ confirmation message with the target's ETH address
        pq_message = create_pq_registration_confirmation_message(
            target_eth_actor_data["eth_address"],  # Use target's ETH address in PQ message
            base_eth_message,
            eth_signature["v"],
            eth_signature["r"],
            eth_signature["s"],
            pq_nonce
        )
        
        # Generate PQ signature using Alice's PQ key (the one with pending intent)
        pq_signature = generate_epervier_signature(pq_message, "alice")
        
        return {
            "eth_actor": eth_actor,
            "target_eth_actor": target_eth_actor,
            "eth_address": target_eth_actor_data["eth_address"],
            "pq_fingerprint": alice_data["pq_fingerprint"],  # Return Alice's PQ fingerprint
            "base_eth_message": base_eth_message.hex(),
            "eth_signature": eth_signature,
            "pq_message": pq_message.hex(),
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }

def main():
    """Generate advanced test vectors in working format for specific scenarios"""
    print("Generating advanced test vectors in working format...")
    
    # Get the project root directory (three levels up from this script)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(script_dir)))
    
    # Create output directories with absolute paths
    advanced_dir = os.path.join(project_root, "test", "test_vectors", "advanced")
    test_vectors_dir = os.path.join(project_root, "test", "test_vectors")
    os.makedirs(advanced_dir, exist_ok=True)
    os.makedirs(test_vectors_dir, exist_ok=True)
    
    generator = AdvancedVectorGenerator()
    
    # Generate scenario vectors
    scenarios = [
        {
            "name": "test4_pq_cancels_change_eth",
            "config": {
                "registration_intent": {"actor": "alice", "eth_nonce": 0, "pq_nonce": 0},
                "registration_confirmation": {"actor": "alice", "eth_nonce": 1, "pq_nonce": 1},
                "change_eth_address_intent": [
                    {"actor": "alice", "new_eth_address": "bob", "eth_nonce": 0, "pq_nonce": 2},
                    {"actor": "alice", "new_eth_address": "charlie", "eth_nonce": 0, "pq_nonce": 3}
                ],
                "removal_change_pq": [
                    {"actor": "alice", "removal_type": "change_pq", "eth_nonce": 2, "pq_nonce": 3}
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
            "name": "multiple_registration_attempts_alice_pq_switches_targets",
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
                    {"eth_actor": "charlie", "target_eth_actor": "charlie", "eth_nonce": 1, "pq_nonce": 4}
                ]
            }
        },
        {
            "name": "multiple_change_attempts",
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
        }
    ]
    
    for scenario in scenarios:
        print(f"Generating vectors for scenario: {scenario['name']}")
        vectors = generator.generate_scenario_vectors(scenario["name"], scenario["config"])
        
        # Save individual vector files
        for vector_type, vector_data in vectors.items():
            if vector_data:
                output_file = os.path.join(advanced_dir, f"{scenario['name']}_{vector_type}_vectors.json")
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
        
        # Save combined scenario file
        combined_file = os.path.join(advanced_dir, f"{scenario['name']}_vectors.json")
        vectors_hex = {k: ([bytes_to_hex(v) for v in vlist] if isinstance(vlist, list) else bytes_to_hex(vlist)) for k, vlist in vectors.items()}
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
    output_file = os.path.join(test_vectors_dir, "pq_registration_eth_removal_retry_vector.json")
    with open(output_file, 'w') as f:
        json.dump({"pq_registration_eth_removal_retry_vector": [bob_confirmation_vector_hex]}, f, indent=2)
    print(f"Saved pq_registration_eth_removal_retry_vector to: {output_file}")
    
    print("\nAdvanced vector generation complete in working format!")

if __name__ == "__main__":
    main() 
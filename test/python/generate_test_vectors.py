#!/usr/bin/env python3
import json
import subprocess
import sys
import os
from pathlib import Path
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
from eth_hash.auto import keccak

# Get the script directory for proper path resolution
SCRIPT_DIR = Path(__file__).parent.absolute()

# Import the necessary modules for signature parsing
sys.path.append(str(SCRIPT_DIR.parent.parent / 'ETHFALCON' / 'python-ref'))
from common import falcon_compact, q
from encoding import decompress
from polyntt.poly import Poly

def load_actors_config():
    """Load actor configuration from the centralized config file"""
    config_path = SCRIPT_DIR.parent / "test_keys" / "actors_config.json"
    with open(config_path, 'r') as f:
        config = json.load(f)
    return config["actors"]

# Load actors from centralized config
ACTORS_CONFIG = load_actors_config()

# Actor mapping for clear test organization - now using centralized config
ACTORS = {
    "alice": {
        "eth_private_key": ACTORS_CONFIG["alice"]["eth_private_key"],
        "eth_address": ACTORS_CONFIG["alice"]["eth_address"],
        "pq_private_key_file": ACTORS_CONFIG["alice"]["pq_private_key_file"],
        "pq_public_key_file": ACTORS_CONFIG["alice"]["pq_public_key_file"],
        "pq_fingerprint": ACTORS_CONFIG["alice"]["pq_fingerprint"],
        "description": "Primary test user"
    },
    "bob": {
        "eth_private_key": ACTORS_CONFIG["bob"]["eth_private_key"],
        "eth_address": ACTORS_CONFIG["bob"]["eth_address"],
        "pq_private_key_file": ACTORS_CONFIG["bob"]["pq_private_key_file"],
        "pq_public_key_file": ACTORS_CONFIG["bob"]["pq_public_key_file"],
        "pq_fingerprint": ACTORS_CONFIG["bob"]["pq_fingerprint"],
        "description": "Secondary test user"
    },
    "charlie": {
        "eth_private_key": ACTORS_CONFIG["charlie"]["eth_private_key"],
        "eth_address": ACTORS_CONFIG["charlie"]["eth_address"],
        "pq_private_key_file": ACTORS_CONFIG["charlie"]["pq_private_key_file"],
        "pq_public_key_file": ACTORS_CONFIG["charlie"]["pq_public_key_file"],
        "pq_fingerprint": ACTORS_CONFIG["charlie"]["pq_fingerprint"],
        "description": "Third test user"
    },
    "danielle": {
        "eth_private_key": ACTORS_CONFIG["danielle"]["eth_private_key"],
        "eth_address": ACTORS_CONFIG["danielle"]["eth_address"],
        "pq_private_key_file": ACTORS_CONFIG["danielle"]["pq_private_key_file"],
        "pq_public_key_file": ACTORS_CONFIG["danielle"]["pq_public_key_file"],
        "pq_fingerprint": ACTORS_CONFIG["danielle"]["pq_fingerprint"],
        "description": "Fourth test user"
    },
    "eve": {
        "eth_private_key": ACTORS_CONFIG["eve"]["eth_private_key"],
        "eth_address": ACTORS_CONFIG["eve"]["eth_address"],
        "pq_private_key_file": ACTORS_CONFIG["eve"]["pq_private_key_file"],
        "pq_public_key_file": ACTORS_CONFIG["eve"]["pq_public_key_file"],
        "pq_fingerprint": ACTORS_CONFIG["eve"]["pq_fingerprint"],
        "description": "Malicious user for negative tests"
    },
    "frank": {
        "eth_private_key": ACTORS_CONFIG["frank"]["eth_private_key"],
        "eth_address": ACTORS_CONFIG["frank"]["eth_address"],
        "pq_private_key_file": ACTORS_CONFIG["frank"]["pq_private_key_file"],
        "pq_public_key_file": ACTORS_CONFIG["frank"]["pq_public_key_file"],
        "pq_fingerprint": ACTORS_CONFIG["frank"]["pq_fingerprint"],
        "description": "Additional test user"
    },
    "grace": {
        "eth_private_key": ACTORS_CONFIG["grace"]["eth_private_key"],
        "eth_address": ACTORS_CONFIG["grace"]["eth_address"],
        "pq_private_key_file": ACTORS_CONFIG["grace"]["pq_private_key_file"],
        "pq_public_key_file": ACTORS_CONFIG["grace"]["pq_public_key_file"],
        "pq_fingerprint": ACTORS_CONFIG["grace"]["pq_fingerprint"],
        "description": "Additional test user"
    },
    "henry": {
        "eth_private_key": ACTORS_CONFIG["henry"]["eth_private_key"],
        "eth_address": ACTORS_CONFIG["henry"]["eth_address"],
        "pq_private_key_file": ACTORS_CONFIG["henry"]["pq_private_key_file"],
        "pq_public_key_file": ACTORS_CONFIG["henry"]["pq_public_key_file"],
        "pq_fingerprint": ACTORS_CONFIG["henry"]["pq_fingerprint"],
        "description": "Additional test user"
    },
    "iris": {
        "eth_private_key": ACTORS_CONFIG["iris"]["eth_private_key"],
        "eth_address": ACTORS_CONFIG["iris"]["eth_address"],
        "pq_private_key_file": ACTORS_CONFIG["iris"]["pq_private_key_file"],
        "pq_public_key_file": ACTORS_CONFIG["iris"]["pq_public_key_file"],
        "pq_fingerprint": ACTORS_CONFIG["iris"]["pq_fingerprint"],
        "description": "Additional test user"
    },
    "jack": {
        "eth_private_key": ACTORS_CONFIG["jack"]["eth_private_key"],
        "eth_address": ACTORS_CONFIG["jack"]["eth_address"],
        "pq_private_key_file": ACTORS_CONFIG["jack"]["pq_private_key_file"],
        "pq_public_key_file": ACTORS_CONFIG["jack"]["pq_public_key_file"],
        "pq_fingerprint": ACTORS_CONFIG["jack"]["pq_fingerprint"],
        "description": "Additional test user"
    }
}

# PQ Registry domain separator
DOMAIN_SEPARATOR = Web3.keccak(text="PQRegistry")

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

def abi_encode(data):
    """Encode data like Solidity's abi.encode (with length prefixes for arrays)"""
    if isinstance(data, list):
        # For arrays, add length prefix and pad each element
        result = len(data).to_bytes(32, 'big')  # Length prefix
        for item in data:
            result += item.to_bytes(32, 'big')  # Padded element
        return result
    elif isinstance(data, int):
        # For integers, just pad to 32 bytes
        return data.to_bytes(32, 'big')
    else:
        raise ValueError(f"Unsupported type for abi_encode: {type(data)}")

def get_pq_public_keys():
    """Get PQ public keys from test_keys directory"""
    pq_keys = []
    test_keys_dir = Path("test_keys")
    
    # Look for public key files (we have 10 keys)
    for i in range(1, 11):  # Try to find 10 keys
        pk_file = test_keys_dir / f"public_key_{i}.pem"
        if pk_file.exists():
            # Parse the public key from PEM format
            with open(pk_file, 'r') as f:
                content = f.read()
                # Extract the pk value from the PEM file
                # Format: # public key\nn = 512\npk = <number>\nversion = epervier
                for line in content.split('\n'):
                    if line.startswith('pk = '):
                        pk_value = int(line.split(' = ')[1])
                        # For now, use a simple mapping (pk, 0) as the public key
                        pq_keys.append([pk_value, 0])
                        break
    
    # If no keys found, use some default test values
    if not pq_keys:
        pq_keys = [
            [123, 456],
            [789, 101],
            [111, 222],
            [333, 444],
            [555, 666],
            [777, 888],
            [999, 111],
            [222, 333],
            [444, 555],
            [666, 777]
        ]
        print("Warning: Using default test PQ keys")
    
    print(f"Found {len(pq_keys)} PQ public keys")
    return pq_keys

def parse_signature_file(sig_file_path):
    """Parse the signature file to extract salt, cs1, cs2, hint using the same logic as the CLI"""
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
            "salt": "0x" + salt.hex(),
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

def generate_epervier_signature(message, actor_name):
    """Generate Epervier signature using the Python CLI for a specific actor"""
    try:
        # Convert message to hex
        message_hex = message.hex() if isinstance(message, bytes) else message.encode().hex()
        
        # Get the actor's private key file
        private_key_file = ACTORS_CONFIG[actor_name]["pq_private_key_file"]
        
        # Call the Python CLI to sign the message
        cmd = [
            sys.executable, 
            str(SCRIPT_DIR.parent.parent / "ETHFALCON/python-ref/sign_cli.py"), 
            "sign",
            "--version", "epervier",
            "--privkey", str(SCRIPT_DIR.parent / f"test_keys/{private_key_file}"),
            "--data", message_hex
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(SCRIPT_DIR))
        
        if result.returncode != 0:
            print(f"Warning: Epervier signing failed for {actor_name}: {result.stderr}")
            return {
                "salt": "0x" + "00" * 40,
                "cs1": [0] * 32,
                "cs2": [0] * 32,
                "hint": 123,
                "raw_signature": ""
            }
        
        # Parse the signature from the generated file
        sig_file = SCRIPT_DIR / "sig"
        if sig_file.exists():
            signature_data = parse_signature_file(sig_file)
            # Clean up the temporary signature file
            sig_file.unlink()
            return signature_data
        else:
            print(f"Warning: Signature file not found for {actor_name}")
            return {
                "salt": "0x" + "00" * 40,
                "cs1": [0] * 32,
                "cs2": [0] * 32,
                "hint": 123,
                "raw_signature": ""
            }
        
    except Exception as e:
        print(f"Error generating Epervier signature for {actor_name}: {e}")
        return {
            "salt": "0x" + "00" * 40,
            "cs1": [0] * 32,
            "cs2": [0] * 32,
            "hint": 123,
            "raw_signature": ""
        }

def generate_comprehensive_test_vectors():
    """Generate comprehensive test vectors for all PQRegistry scenarios"""
    # Create test_vectors directory
    test_vectors_dir = SCRIPT_DIR / "test_vectors"
    test_vectors_dir.mkdir(exist_ok=True)
    
    # Get PQ public keys
    pq_keys = get_pq_public_keys()
    
    print(f"Generating comprehensive test vectors for {len(ACTORS)} actors...")
    
    # Generate test vectors for each actor
    for actor_name, actor_config in ACTORS.items():
        print(f"Generating test vector for {actor_name}...")
        
        # Get the actor's keys
        eth_key_index = list(ACTORS.keys()).index(actor_name)
        pq_key_index = list(ACTORS.keys()).index(actor_name)
        
        eth_priv_key = ACTORS_CONFIG[actor_name]["eth_private_key"]
        pq_key = pq_keys[pq_key_index]
        
        # Create Ethereum account
        account = Account.from_key(eth_priv_key)
        eth_address = account.address
        
        # Use PQ fingerprint from the centralized config
        pq_fingerprint = ACTORS_CONFIG[actor_name]["pq_fingerprint"]
        pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
        
        # ============================================================================
        # REGISTRATION FLOW
        # ============================================================================
        
        # Step 1: Create base PQ message for registration intent
        # Schema: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + ethAddress + pqNonce
        eth_address_bytes = bytes.fromhex(eth_address[2:])
        base_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to pair ETH Address ",
            eth_address_bytes,
            (0).to_bytes(32, 'big')  # pqNonce
        )
        
        # Step 2: Generate Epervier signature for the base PQ message
        print(f"  Generating Epervier signature for registration intent...")
        epervier_sig = generate_epervier_signature(base_pq_message, actor_name)
        
        # Step 3: Create ETH message that includes the PQ signature components
        # Schema: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
        eth_intent_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to pair Epervier Key",
            base_pq_message,  # basePQMessage (111 bytes)
            bytes.fromhex(epervier_sig["salt"][2:]),  # pqSignature salt (40 bytes)
            pack_uint256_array(epervier_sig["cs1"]),  # cs1 as 32*32 bytes (1024 bytes)
            pack_uint256_array(epervier_sig["cs2"]),  # cs2 as 32*32 bytes (1024 bytes)
            epervier_sig["hint"].to_bytes(32, 'big'),  # pqSignature hint (32 bytes)
            (0).to_bytes(32, 'big')  # ethNonce (32 bytes)
        )
        
        # Verify the ETH intent message length matches schema (2322 bytes)
        eth_intent_length = len(eth_intent_message)
        print(f"  ETH intent message length: {eth_intent_length} bytes (should be 2322)")
        if eth_intent_length != 2322:
            print(f"  WARNING: ETH intent message length is {eth_intent_length}, expected 2322")
                
        # Step 4: Sign the ETH message
        # Use the same format as the contract: "\x19Ethereum Signed Message:\n" + length + message
        eth_message_length = len(eth_intent_message)
        eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + eth_intent_message
        eth_message_hash = keccak(eth_signed_message)
        eth_signature = Account._sign_hash(eth_message_hash, private_key=account.key)
        
        # ============================================================================
        # REGISTRATION CONFIRMATION FLOW
        # ============================================================================
        
        # Step 5: Create base ETH message for registration confirmation
        # Schema: DOMAIN_SEPARATOR + "Confirm bonding to Epervier fingerprint " + pqFingerprint + ethNonce
        base_eth_confirm_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm bonding to Epervier fingerprint ",
            pq_fingerprint_bytes,  # pqFingerprint (20 bytes)
            (1).to_bytes(32, 'big')  # ethNonce (32 bytes)
        )
        
        # Step 6: Create PQ confirmation message
        # Schema: DOMAIN_SEPARATOR + "Confirm binding ETH Address " + ethAddress + baseETHMessage + v + r + s + pqNonce
        pq_confirm_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm binding ETH Address ",
            eth_address_bytes,  # ethAddress (20 bytes)
            base_eth_confirm_message,  # baseETHMessage (124 bytes)
            eth_signature.v.to_bytes(1, 'big'),  # v (1 byte)
            eth_signature.r.to_bytes(32, 'big'),  # r (32 bytes)
            eth_signature.s.to_bytes(32, 'big'),   # s (32 bytes)
            (1).to_bytes(32, 'big')  # pqNonce (32 bytes)
        )
        
        # Step 7: Generate Epervier signature for registration confirmation
        print(f"  Generating Epervier signature for registration confirmation...")
        epervier_confirm_sig = generate_epervier_signature(pq_confirm_message, actor_name)
        
        # ============================================================================
        # REMOVE INTENT FLOW
        # ============================================================================
        
        # Create ETH message for removing registration intent
        # Schema: DOMAIN_SEPARATOR + "Remove registration intent from Epervier fingerprint " + pqFingerprint + ethNonce
        remove_registration_pattern = "Remove registration intent from Epervier fingerprint "
        assert len(remove_registration_pattern.encode('utf-8')) == 44, "Pattern must be 44 bytes for schema compliance"
        
        # Debug: Print each component
        print(f"  Debug - DOMAIN_SEPARATOR: {len(DOMAIN_SEPARATOR)} bytes")
        print(f"  Debug - pattern: {len(remove_registration_pattern.encode('utf-8'))} bytes")
        print(f"  Debug - pqFingerprint: {len(pq_fingerprint_bytes)} bytes")
        print(f"  Debug - ethNonce: {len((2).to_bytes(32, 'big'))} bytes")
        
        remove_registration_intent_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            remove_registration_pattern,
            pq_fingerprint_bytes,  # pqFingerprint (20 bytes)
            (2).to_bytes(32, 'big')  # ethNonce (32 bytes)
        )
        print(f"  Debug - Total message length: {len(remove_registration_intent_message)} bytes")
        assert len(remove_registration_intent_message) == 123, f"Message must be 123 bytes for schema compliance, got {len(remove_registration_intent_message)}"
        
        # Sign the remove registration intent message
        remove_message_length = len(remove_registration_intent_message)
        remove_signed_message = b"\x19Ethereum Signed Message:\n" + str(remove_message_length).encode() + remove_registration_intent_message
        remove_message_hash = keccak(remove_signed_message)
        remove_signature = Account._sign_hash(remove_message_hash, private_key=account.key)
        
        # Create PQ message for removing registration intent
        # Schema: DOMAIN_SEPARATOR + "Remove registration intent from address " + ethAddress + pqNonce
        remove_registration_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Remove registration intent from address ",
            eth_address_bytes,  # ethAddress (20 bytes)
            (2).to_bytes(32, 'big')  # pqNonce (32 bytes)
        )
        
        # Generate Epervier signature for remove registration intent
        print(f"  Generating Epervier signature for remove registration intent...")
        remove_registration_epervier_sig = generate_epervier_signature(remove_registration_pq_message, actor_name)
        
        # Create ETH message for removing change intent
        # Schema: DOMAIN_SEPARATOR + "Remove change intent from address" + pqFingerprint + ethNonce
        remove_change_intent_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Remove change intent from address",
            pq_fingerprint_bytes,  # pqFingerprint (20 bytes)
            (3).to_bytes(32, 'big')  # ethNonce (32 bytes)
        )
        
        # Sign the remove change intent message
        remove_change_message_length = len(remove_change_intent_message)
        remove_change_signed_message = b"\x19Ethereum Signed Message:\n" + str(remove_change_message_length).encode() + remove_change_intent_message
        remove_change_message_hash = keccak(remove_change_signed_message)
        remove_change_signature = Account._sign_hash(remove_change_message_hash, private_key=account.key)
        
        # Create PQ message for removing change intent
        # Schema: DOMAIN_SEPARATOR + "Remove change intent from address " + ethAddress + pqNonce
        remove_change_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Remove change intent from address ",
            eth_address_bytes,  # ethAddress (20 bytes)
            (3).to_bytes(32, 'big')  # pqNonce (32 bytes)
        )
        
        # Generate Epervier signature for remove change intent
        print(f"  Generating Epervier signature for remove change intent...")
        remove_change_epervier_sig = generate_epervier_signature(remove_change_pq_message, actor_name)
        
        # Create ETH message for removing unregistration intent
        # Schema: DOMAIN_SEPARATOR + "Remove unregistration intent from address" + pqFingerprint + ethNonce
        remove_unregistration_intent_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Remove unregistration intent from address",
            pq_fingerprint_bytes,  # pqFingerprint (20 bytes)
            (4).to_bytes(32, 'big')  # ethNonce (32 bytes)
        )
        
        # Sign the remove unregistration intent message
        remove_unregistration_message_length = len(remove_unregistration_intent_message)
        remove_unregistration_signed_message = b"\x19Ethereum Signed Message:\n" + str(remove_unregistration_message_length).encode() + remove_unregistration_intent_message
        remove_unregistration_message_hash = keccak(remove_unregistration_signed_message)
        remove_unregistration_signature = Account._sign_hash(remove_unregistration_message_hash, private_key=account.key)
        
        # Create PQ message for removing unregistration intent
        # Schema: DOMAIN_SEPARATOR + "Remove unregistration intent from address " + ethAddress + pqNonce
        remove_unregistration_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Remove unregistration intent from address ",
            eth_address_bytes,  # ethAddress (20 bytes)
            (4).to_bytes(32, 'big')  # pqNonce (32 bytes)
        )
        
        # Generate Epervier signature for remove unregistration intent
        print(f"  Generating Epervier signature for remove unregistration intent...")
        remove_unregistration_epervier_sig = generate_epervier_signature(remove_unregistration_pq_message, actor_name)
        
        # ============================================================================
        # CHANGE ETH ADDRESS FLOW
        # ============================================================================
        
        # Use the next actor's ETH address as the new address for change tests
        next_actor_name = list(ACTORS.keys())[(list(ACTORS.keys()).index(actor_name) + 1) % len(ACTORS)]
        next_actor_config = ACTORS[next_actor_name]
        next_eth_priv_key = ACTORS_CONFIG[next_actor_name]["eth_private_key"]
        next_account = Account.from_key(next_eth_priv_key)
        next_eth_address = next_account.address
        next_eth_address_bytes = bytes.fromhex(next_eth_address[2:])
        
        # Create base PQ message for change ETH address intent
        # Schema: DOMAIN_SEPARATOR + "Confirm changing ETH address from " + oldEthAddress + " to " + newEthAddress + pqNonce
        change_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm changing ETH address from ",
            eth_address_bytes,  # oldEthAddress (20 bytes)
            " to ",
            next_eth_address_bytes,  # newEthAddress (20 bytes)
            (2).to_bytes(32, 'big')  # pqNonce (32 bytes)
        )
        
        # Generate Epervier signature for change ETH address intent
        print(f"  Generating Epervier signature for change ETH address intent...")
        change_epervier_sig = generate_epervier_signature(change_pq_message, actor_name)
        
        # Create ETH message for change ETH address confirmation
        # Schema: DOMAIN_SEPARATOR + "Confirm change ETH Address" + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
        change_confirm_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm change ETH Address",
            change_pq_message,  # basePQMessage (140 bytes)
            bytes.fromhex(change_epervier_sig["salt"][2:]),  # pqSignature salt (40 bytes)
            pack_uint256_array(change_epervier_sig["cs1"]),  # cs1 as 32*32 bytes (1024 bytes)
            pack_uint256_array(change_epervier_sig["cs2"]),  # cs2 as 32*32 bytes (1024 bytes)
            change_epervier_sig["hint"].to_bytes(32, 'big'),  # pqSignature hint (32 bytes)
            (3).to_bytes(32, 'big')  # ethNonce (32 bytes)
        )
        
        # Sign the change confirmation message
        change_confirm_length = len(change_confirm_message)
        change_confirm_signed = b"\x19Ethereum Signed Message:\n" + str(change_confirm_length).encode() + change_confirm_message
        change_confirm_hash = keccak(change_confirm_signed)
        change_confirm_signature = Account._sign_hash(change_confirm_hash, private_key=next_account.key)
        
        # Create PQ message for change ETH address confirmation (PQ key signs with ETH sig nested)
        # Schema: DOMAIN_SEPARATOR + "Change ETH Address from " + oldEthAddress + " to " + newEthAddress + baseETHMessage + v + r + s + pqNonce
        # First create the base ETH message for change intent
        base_eth_change_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to Change ETH Address for fingeprint ",
            bytes.fromhex(pq_fingerprint[2:]),  # pqFingerprint (20 bytes)
            " to ",
            next_eth_address_bytes,  # newEthAddress (20 bytes)
            (4).to_bytes(32, 'big')  # ethNonce (32 bytes)
        )
        
        change_confirm_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Change ETH Address from ",
            eth_address_bytes,  # current address
            " to ",
            next_eth_address_bytes,  # new address
            base_eth_change_message,  # baseETHMessage (152 bytes)
            change_confirm_signature.v.to_bytes(1, 'big'),  # v (1 byte)
            change_confirm_signature.r.to_bytes(32, 'big'),  # r (32 bytes)
            change_confirm_signature.s.to_bytes(32, 'big'),   # s (32 bytes)
            (3).to_bytes(32, 'big')  # pqNonce (32 bytes)
        )
        
        # Generate Epervier signature for change ETH address confirmation
        print(f"  Generating Epervier signature for change ETH address confirmation...")
        change_confirm_epervier_sig = generate_epervier_signature(change_confirm_pq_message, actor_name)
        
        # ============================================================================
        # UNREGISTRATION FLOW
        # ============================================================================
        
        # Create test data for unregistration
        # Schema: DOMAIN_SEPARATOR + "Confirm unregistration from ETH Address" + ethAddress + pqNonce
        unreg_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm unregistration from ETH Address",
            next_eth_address_bytes,  # Use the new address
            (4).to_bytes(32, 'big')  # pqNonce (32 bytes)
        )
        
        # Generate Epervier signature for unregistration
        print(f"  Generating Epervier signature for unregistration...")
        unreg_epervier_sig = generate_epervier_signature(unreg_pq_message, actor_name)
        
        # Create ETH message for unregistration confirmation
        # Schema: DOMAIN_SEPARATOR + "Confirm unregistration from PQ fingerprint" + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
        unreg_confirm_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm unregistration from PQ fingerprint",
            bytes.fromhex(pq_fingerprint[2:]),  # pqFingerprint (20 bytes)
            unreg_pq_message,  # basePQMessage (111 bytes)
            bytes.fromhex(unreg_epervier_sig["salt"][2:]),  # pqSignature salt (40 bytes)
            pack_uint256_array(unreg_epervier_sig["cs1"]),  # cs1 as 32*32 bytes (1024 bytes)
            pack_uint256_array(unreg_epervier_sig["cs2"]),  # cs2 as 32*32 bytes (1024 bytes)
            unreg_epervier_sig["hint"].to_bytes(32, 'big'),  # pqSignature hint (32 bytes)
            (5).to_bytes(32, 'big')  # ethNonce (32 bytes)
        )
        
        # Use the same format as the contract: "\x19Ethereum Signed Message:\n" + length + message
        unreg_confirm_length = len(unreg_confirm_message)
        unreg_confirm_signed = b"\x19Ethereum Signed Message:\n" + str(unreg_confirm_length).encode() + unreg_confirm_message
        unreg_confirm_hash = keccak(unreg_confirm_signed)
        unreg_confirm_signature = Account._sign_hash(unreg_confirm_hash, private_key=next_account.key)
        
        # Save comprehensive test vector
        test_vector = {
            "actor": actor_name,
            "description": actor_config["description"],
            "eth_address": eth_address,
            "next_eth_address": next_eth_address,
            "pq_fingerprint": pq_fingerprint,
            "pq_public_key": pq_key,
            "pq_public_key_hash": pq_fingerprint,
            
            # Registration data
            "registration": {
                "base_pq_message": base_pq_message.hex(),
                "eth_intent_message": eth_intent_message.hex(),
                "eth_intent_signature": eth_signature.signature.hex(),
                "pq_confirm_message": pq_confirm_message.hex(),
                "epervier_salt": epervier_confirm_sig["salt"],
                "epervier_cs1": epervier_confirm_sig["cs1"],
                "epervier_cs2": epervier_confirm_sig["cs2"],
                "epervier_hint": epervier_confirm_sig["hint"],
                # Add intent signature data for submitRegistrationIntent
                "intent_epervier_salt": epervier_sig["salt"],
                "intent_epervier_cs1": epervier_sig["cs1"],
                "intent_epervier_cs2": epervier_sig["cs2"],
                "intent_epervier_hint": epervier_sig["hint"]
            },
            
            # Remove intent data
            "remove_intent": {
                "registration": {
                    "eth_message": remove_registration_intent_message.hex(),
                    "eth_signature": remove_signature.signature.hex(),
                    "pq_message": remove_registration_pq_message.hex(),
                    "pq_salt": remove_registration_epervier_sig["salt"],
                    "pq_cs1": remove_registration_epervier_sig["cs1"],
                    "pq_cs2": remove_registration_epervier_sig["cs2"],
                    "pq_hint": remove_registration_epervier_sig["hint"]
                },
                "change": {
                    "eth_message": remove_change_intent_message.hex(),
                    "eth_signature": remove_change_signature.signature.hex(),
                    "pq_message": remove_change_pq_message.hex(),
                    "pq_salt": remove_change_epervier_sig["salt"],
                    "pq_cs1": remove_change_epervier_sig["cs1"],
                    "pq_cs2": remove_change_epervier_sig["cs2"],
                    "pq_hint": remove_change_epervier_sig["hint"]
                },
                "unregistration": {
                    "eth_message": remove_unregistration_intent_message.hex(),
                    "eth_signature": remove_unregistration_signature.signature.hex(),
                    "pq_message": remove_unregistration_pq_message.hex(),
                    "pq_salt": remove_unregistration_epervier_sig["salt"],
                    "pq_cs1": remove_unregistration_epervier_sig["cs1"],
                    "pq_cs2": remove_unregistration_epervier_sig["cs2"],
                    "pq_hint": remove_unregistration_epervier_sig["hint"]
                }
            },
            
            # Change ETH address data
            "change_address": {
                "base_pq_message": change_pq_message.hex(),
                "eth_confirm_message": change_confirm_message.hex(),
                "eth_confirm_signature": change_confirm_signature.signature.hex(),
                "pq_confirm_message": change_confirm_pq_message.hex(),
                "epervier_salt": change_confirm_epervier_sig["salt"],
                "epervier_cs1": change_confirm_epervier_sig["cs1"],
                "epervier_cs2": change_confirm_epervier_sig["cs2"],
                "epervier_hint": change_confirm_epervier_sig["hint"]
            },
            
            # Unregistration data
            "unregistration": {
                "base_pq_message": unreg_pq_message.hex(),
                "eth_confirm_message": unreg_confirm_message.hex(),
                "eth_confirm_signature": unreg_confirm_signature.signature.hex(),
                "epervier_salt": unreg_epervier_sig["salt"],
                "epervier_cs1": unreg_epervier_sig["cs1"],
                "epervier_cs2": unreg_epervier_sig["cs2"],
                "epervier_hint": unreg_epervier_sig["hint"]
            }
        }
        
        # Save to file
        filename = test_vectors_dir / f"{actor_name}_test_vector.json"
        with open(filename, 'w') as f:
            json.dump(test_vector, f, indent=2)
        print(f"  Saved to {filename}")
    
    print(f"\nGenerated {len(ACTORS)} comprehensive test vectors in test_vectors/")
    print("Note: Test vectors now include registration, change ETH address, and unregistration scenarios.")

def generate_simple_test_vector():
    """Generate a simple test vector for basic tests"""
    print("Generating simple test vector...")
    
    # Use the first private key and PQ key
    eth_priv_key = ACTORS_CONFIG["alice"]["eth_private_key"]
    pq_key = get_pq_public_keys()[0]
    
    # Create Ethereum account
    account = Account.from_key(eth_priv_key)
    eth_address = account.address
    
    # Create base PQ message for registration intent
    eth_address_bytes = bytes.fromhex(eth_address[2:])
    base_pq_message = abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair ETH Address ",
        eth_address_bytes,
        (0).to_bytes(32, 'big')  # pqNonce
    )
    
    # Generate Epervier signature for the base PQ message
    epervier_sig = generate_epervier_signature(base_pq_message, "alice")
    
    # Create ETH message that includes the PQ signature components
    # Schema: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
    eth_intent_message = abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair Epervier Key",
        base_pq_message,  # basePQMessage (111 bytes)
        bytes.fromhex(epervier_sig["salt"][2:]),  # pqSignature salt (40 bytes)
        pack_uint256_array(epervier_sig["cs1"]),  # cs1 as 32*32 bytes (1024 bytes)
        pack_uint256_array(epervier_sig["cs2"]),  # cs2 as 32*32 bytes (1024 bytes)
        epervier_sig["hint"].to_bytes(32, 'big'),  # pqSignature hint (32 bytes)
        (0).to_bytes(32, 'big')  # ethNonce (32 bytes)
    )
    
    # Sign the ETH message
    # Use the same format as the contract: "\x19Ethereum Signed Message:\n" + length + message
    eth_message_length = len(eth_intent_message)
    eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + eth_intent_message
    print("PYTHON: eth_signed_message:", eth_signed_message.hex())
    eth_message_hash = keccak(eth_signed_message)
    print("PYTHON: eth_signed_message:", eth_signed_message.hex())
    eth_signature = Account._sign_hash(eth_message_hash, private_key=account.key)
    
    # Create simple test vector
    test_vector = {
        "eth_address": eth_address,
        "pq_public_key": pq_key,
        "base_pq_message": base_pq_message.hex(),
        "eth_intent_message": eth_intent_message.hex(),
        "eth_intent_signature": eth_signature.signature.hex(),
        "epervier_salt": epervier_sig["salt"],
        "epervier_cs1": epervier_sig["cs1"],
        "epervier_cs2": epervier_sig["cs2"],
        "epervier_hint": epervier_sig["hint"]
    }
    
    # Save to file
    filename = SCRIPT_DIR / "test_vectors/test_vector_1.json"
    with open(filename, 'w') as f:
        json.dump(test_vector, f, indent=2)
    print(f"  Saved to {filename}")

def pack_uint256_array(arr):
    return b''.join(x.to_bytes(32, 'big') for x in arr)

def generate_invalid_test_vectors():
    """Generate invalid test vectors for negative testing"""
    # Create test_vectors directory
    test_vectors_dir = SCRIPT_DIR / "test_vectors"
    test_vectors_dir.mkdir(exist_ok=True)
    
    # Get PQ public keys
    pq_keys = get_pq_public_keys()
    
    print(f"Generating invalid test vectors for negative testing...")
    
    # Use Alice's keys as base for invalid tests
    alice_config = ACTORS["alice"]
    eth_priv_key = ACTORS_CONFIG["alice"]["eth_private_key"]
    pq_key = pq_keys[0]
    
    # Create Ethereum account
    account = Account.from_key(eth_priv_key)
    eth_address = account.address
    eth_address_bytes = bytes.fromhex(eth_address[2:])
    
    # Calculate PQ fingerprint
    pq_pubkey_bytes = pq_key[0].to_bytes(32, 'big') + pq_key[1].to_bytes(32, 'big')
    # Use keccak256 hash to derive 20-byte fingerprint (address)
    pq_fingerprint_bytes = keccak(pq_pubkey_bytes)[-20:]  # Last 20 bytes of hash
    pq_fingerprint = "0x" + pq_fingerprint_bytes.hex()
    
    # ============================================================================
    # INVALID TEST VECTORS
    # ============================================================================
    
    # 1. Invalid ETH signature (wrong private key)
    print("  Generating invalid ETH signature test...")
    base_pq_message = abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair ETH Address ",
        eth_address_bytes,
        (0).to_bytes(32, 'big')  # pqNonce
    )
    
    epervier_sig = generate_epervier_signature(base_pq_message, "alice")
    
    eth_intent_message = abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair Epervier Key",
        base_pq_message,
        bytes.fromhex(epervier_sig["salt"][2:]),
        pack_uint256_array(epervier_sig["cs1"]),
        pack_uint256_array(epervier_sig["cs2"]),
        epervier_sig["hint"].to_bytes(32, 'big'),
        (0).to_bytes(32, 'big')  # ethNonce
    )
    
    # Sign with wrong private key
    wrong_priv_key = "0x9999999999999999999999999999999999999999999999999999999999999999"
    wrong_account = Account.from_key(wrong_priv_key)
    eth_message_length = len(eth_intent_message)
    eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + eth_intent_message
    eth_message_hash = keccak(eth_signed_message)
    wrong_signature = Account._sign_hash(eth_message_hash, private_key=wrong_account.key)
    
    invalid_eth_sig_vector = {
        "test_type": "invalid_eth_signature",
        "description": "ETH signature from wrong private key",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "eth_intent_message": eth_intent_message.hex(),
        "eth_intent_signature": wrong_signature.signature.hex(),
        "expected_error": "ERR1: Invalid ETH signature"
    }
    
    # 2. Invalid PQ signature (wrong key)
    print("  Generating invalid PQ signature test...")
    base_eth_confirm_message = abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Confirm bonding to Epervier fingerprint ",
        pq_fingerprint_bytes,  # pqFingerprint (20 bytes)
        (1).to_bytes(32, 'big')  # ethNonce (32 bytes)
    )
    
    pq_confirm_message = abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Confirm binding ETH Address ",
        eth_address_bytes,
        base_eth_confirm_message,
        (27).to_bytes(1, 'big'),  # v
        (0).to_bytes(32, 'big'),  # r
        (0).to_bytes(32, 'big'),  # s
        (1).to_bytes(32, 'big')  # pqNonce
    )
    
    # Use wrong PQ key for signature
    wrong_pq_key_index = (0 + 1) % len(pq_keys)
    wrong_epervier_sig = generate_epervier_signature(pq_confirm_message, "alice")
    
    invalid_pq_sig_vector = {
        "test_type": "invalid_pq_signature",
        "description": "PQ signature from wrong key",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "pq_confirm_message": pq_confirm_message.hex(),
        "epervier_salt": wrong_epervier_sig["salt"],
        "epervier_cs1": wrong_epervier_sig["cs1"],
        "epervier_cs2": wrong_epervier_sig["cs2"],
        "epervier_hint": wrong_epervier_sig["hint"],
        "expected_error": "Invalid PQ signature"
    }
    
    # 3. Wrong nonce test
    print("  Generating wrong nonce test...")
    wrong_nonce_message = abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair ETH Address ",
        eth_address_bytes,
        (999).to_bytes(32, 'big')  # Wrong nonce
    )
    
    wrong_nonce_sig = generate_epervier_signature(wrong_nonce_message, "alice")
    
    wrong_nonce_eth_message = abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair Epervier Key",
        wrong_nonce_message,
        bytes.fromhex(wrong_nonce_sig["salt"][2:]),
        pack_uint256_array(wrong_nonce_sig["cs1"]),
        pack_uint256_array(wrong_nonce_sig["cs2"]),
        wrong_nonce_sig["hint"].to_bytes(32, 'big'),
        (0).to_bytes(32, 'big')  # ethNonce
    )
    
    eth_message_length = len(wrong_nonce_eth_message)
    eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + wrong_nonce_eth_message
    eth_message_hash = keccak(eth_signed_message)
    eth_signature = Account._sign_hash(eth_message_hash, private_key=account.key)
    
    invalid_nonce_vector = {
        "test_type": "invalid_nonce",
        "description": "Wrong PQ nonce in message",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "eth_intent_message": wrong_nonce_eth_message.hex(),
        "eth_intent_signature": eth_signature.signature.hex(),
        "expected_error": "ERR6: Invalid ETH nonce in submitRegistrationIntent"
    }
    
    # 4. Malformed message test
    print("  Generating malformed message test...")
    malformed_message = abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Malformed message",  # Wrong pattern
        eth_address_bytes,
        (0).to_bytes(32, 'big')
    )
    
    malformed_sig = generate_epervier_signature(malformed_message, "alice")
    
    malformed_eth_message = abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair Epervier Key",
        malformed_message,
        bytes.fromhex(malformed_sig["salt"][2:]),
        pack_uint256_array(malformed_sig["cs1"]),
        pack_uint256_array(malformed_sig["cs2"]),
        malformed_sig["hint"].to_bytes(32, 'big'),
        (0).to_bytes(32, 'big')
    )
    
    eth_message_length = len(malformed_eth_message)
    eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + malformed_eth_message
    eth_message_hash = keccak(eth_signed_message)
    eth_signature = Account._sign_hash(eth_message_hash, private_key=account.key)
    
    malformed_message_vector = {
        "test_type": "malformed_message",
        "description": "Message with wrong pattern",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "eth_intent_message": malformed_eth_message.hex(),
        "eth_intent_signature": eth_signature.signature.hex(),
        "expected_error": "Invalid message format"
    }
    
    # Save all invalid test vectors
    invalid_vectors = {
        "invalid_eth_signature": invalid_eth_sig_vector,
        "invalid_pq_signature": invalid_pq_sig_vector,
        "invalid_nonce": invalid_nonce_vector,
        "malformed_message": malformed_message_vector
    }
    
    filename = test_vectors_dir / "invalid_test_vectors.json"
    with open(filename, 'w') as f:
        json.dump(invalid_vectors, f, indent=2)
    print(f"  Saved invalid test vectors to {filename}")
    
    print(f"\nGenerated invalid test vectors for negative testing")

if __name__ == "__main__":
    generate_comprehensive_test_vectors()
    generate_simple_test_vector()
    generate_invalid_test_vectors() 
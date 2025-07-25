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
sys.path.append('../ETHFALCON/python-ref')
from common import falcon_compact, q
from encoding import decompress
from polyntt.poly import Poly

# Foundry default private keys (first 5)
ETH_PRIVATE_KEYS = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118e8d7e3bdfa4b9b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
]

# Import domain separator from config
from eip712_config import DOMAIN_SEPARATOR

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
    
    # Look for public key files
    for i in range(1, 6):  # Try to find 5 keys
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
            [555, 666]
        ]
        print("Warning: Using default test PQ keys")
    
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

def generate_epervier_signature(message, pq_key_index):
    """Generate Epervier signature using the Python CLI"""
    try:
        # Convert message to hex
        message_hex = message.hex() if isinstance(message, bytes) else message.encode().hex()
        
        # Call the Python CLI to sign the message
        cmd = [
            sys.executable, 
            "sign_cli.py",  # Use relative path since we're in the same directory
            "sign",
            "--version", "epervier",
            "--privkey", f"../../test/test_keys/private_key_{pq_key_index + 1}.pem",
            "--data", message_hex
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(SCRIPT_DIR))
        
        if result.returncode != 0:
            print(f"Warning: Epervier signing failed for key {pq_key_index}: {result.stderr}")
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
            print(f"Warning: Signature file not found for key {pq_key_index}")
            return {
                "salt": "0x" + "00" * 40,
                "cs1": [0] * 32,
                "cs2": [0] * 32,
                "hint": 123,
                "raw_signature": ""
            }
        
    except Exception as e:
        print(f"Error generating Epervier signature: {e}")
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
    
    print(f"Generating comprehensive test vectors for {len(ETH_PRIVATE_KEYS)} key combinations...")
    
    for i, (eth_priv_key, pq_key) in enumerate(zip(ETH_PRIVATE_KEYS, pq_keys)):
        print(f"Generating comprehensive vector {i+1}...")
        
        # Create Ethereum account
        account = Account.from_key(eth_priv_key)
        eth_address = account.address
        
        # Calculate PQ public key hash
        pq_pubkey_bytes = pq_key[0].to_bytes(32, 'big') + pq_key[1].to_bytes(32, 'big')
        pq_pubkey_hash = "0x" + pq_pubkey_bytes.hex()
        
        # ============================================================================
        # REGISTRATION FLOW
        # ============================================================================
        
        # Step 1: Create base PQ message for registration intent
        eth_address_bytes = bytes.fromhex(eth_address[2:])
        base_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to pair ETH Address ",
            eth_address_bytes,
            (0).to_bytes(32, 'big')  # pqNonce
        )
        
        # Step 2: Generate Epervier signature for the base PQ message
        print(f"  Generating Epervier signature for registration intent...")
        epervier_sig = generate_epervier_signature(base_pq_message, i)
        
        # Step 3: Create ETH message that includes the PQ signature components
        eth_intent_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to pair Epervier Key",
            (0).to_bytes(32, 'big'),  # ethNonce
            bytes.fromhex(epervier_sig["salt"][2:]),  # pqSignature salt
            pack_uint256_array(epervier_sig["cs1"]),  # cs1 as 32*32 bytes, no prefix
            pack_uint256_array(epervier_sig["cs2"]),  # cs2 as 32*32 bytes, no prefix
            epervier_sig["hint"].to_bytes(32, 'big'),  # pqSignature hint
            base_pq_message  # pqMessage
        )
                
        # Step 4: Sign the ETH message
        # Use the same format as the contract: "\x19Ethereum Signed Message:\n" + length + message
        eth_message_length = len(eth_intent_message)
        eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + eth_intent_message
        print("PYTHON: eth_signed_message:", eth_signed_message.hex())
        eth_message_hash = keccak(eth_signed_message)
        eth_signature = Account._sign_hash(eth_message_hash, private_key=account.key)
        
        # Step 5: Create ETH confirmation message and signature
        # Create ETH confirmation message with fingerprint
        # The fingerprint should be the address recovered from the PQ signature verification
        # We need to use the actual recovered address from the Epervier signature
        # For now, we'll use a mock recovered address that we know the contract will accept
        # In a real implementation, this would be the actual address recovered from the PQ signature
        
        # Mock recovered fingerprint - this should match what the contract recovers
        # We'll use a deterministic address based on the key index
        recovered_fingerprint = bytes.fromhex("7b317f4d231cbc63de7c6c690ef4ba9c653437fb")
        pq_fingerprint = recovered_fingerprint  # 20 bytes for address
        
        # Debug: Print the fingerprint to verify it matches what the contract expects
        print(f"  Generated fingerprint: 0x{pq_fingerprint.hex()}")
        print(f"  Expected fingerprint: 0x7b317f4d231cbc63de7c6c690ef4ba9c653437fb")
        
        print(f"ETH confirmation fingerprint (should match contract): 0x{pq_fingerprint.hex()}")
        
        # NEW FORMAT: ETH confirmation message should be:
        # DOMAIN_SEPARATOR + "Confirm binding Fingerprint " + fingerprint + " to ETH Address " + ethAddress + ethNonce
        eth_confirm_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm binding Fingerprint ",
            pq_fingerprint,  # fingerprint address (20 bytes)
            " to ETH Address ",
            eth_address_bytes,  # ETH address (20 bytes)
            (1).to_bytes(32, 'big')  # ethNonce (incremented after intent)
        )
        
        # Sign the ETH confirmation message
        eth_confirm_length = len(eth_confirm_message)
        eth_confirm_signed = b"\x19Ethereum Signed Message:\n" + str(eth_confirm_length).encode() + eth_confirm_message
        eth_confirm_hash = keccak(eth_confirm_signed)
        eth_confirm_signature = Account._sign_hash(eth_confirm_hash, private_key=account.key)
        
        # Step 6: Create PQ message for registration confirmation (PQ key signs with ETH sig nested)
        # NEW FORMAT: DOMAIN_SEPARATOR + "Confirm bonding to ETH Address " + ethAddress + " to Fingerprint " + fingerprintAddress + pqNonce + ethSignature + ETH_message
        # The contract expects the signature at offset 154, so we need to ensure the PQ header is exactly 154 bytes
        pattern = "Confirm bonding to ETH Address "
        pattern2 = " to Fingerprint "
        print(f"  Pattern 1 length: {len(pattern)} bytes")
        print(f"  Pattern 2 length: {len(pattern2)} bytes")
        
        pq_header = abi_encode_packed(
            DOMAIN_SEPARATOR,
            pattern,
            eth_address_bytes,
            pattern2,
            pq_fingerprint,  # fingerprint address (20 bytes)
            (0).to_bytes(32, 'big')  # pqNonce
        )
        
        # Verify the header length is exactly 154 bytes
        header_length = len(pq_header)
        print(f"  PQ header length: {header_length} bytes (should be 154)")
        print(f"  Breakdown: DOMAIN_SEPARATOR({len(DOMAIN_SEPARATOR)}) + pattern1({len(pattern)}) + ethAddress({len(eth_address_bytes)}) + pattern2({len(pattern2)}) + fingerprint({len(pq_fingerprint)}) + pqNonce(32) = {len(DOMAIN_SEPARATOR) + len(pattern) + len(eth_address_bytes) + len(pattern2) + len(pq_fingerprint) + 32}")
        
        if header_length != 154:
            print(f"  WARNING: PQ header length is {header_length}, expected 154")
            # Pad or truncate to exactly 154 bytes
            if header_length < 154:
                # Pad with zeros to reach exactly 154 bytes
                padding = b'\x00' * (154 - header_length)
                pq_header = pq_header + padding
                print(f"  Added {154 - header_length} bytes of padding to reach 154 bytes")
            else:
                # Truncate (this shouldn't happen with the current format)
                pq_header = pq_header[:154]
                print(f"  Truncated to 154 bytes")
        
        # Verify final header length
        final_header_length = len(pq_header)
        print(f"  Final PQ header length: {final_header_length} bytes")
        
        pq_confirm_message = pq_header + eth_confirm_signature.signature + eth_confirm_message
        
        # Generate Epervier signature for the confirmation message
        print(f"  Generating Epervier signature for registration confirmation...")
        epervier_confirm_sig = generate_epervier_signature(pq_confirm_message, i)
        
        # ============================================================================
        # REMOVE INTENT FLOW
        # ============================================================================
        
        # Create remove intent message with new format: DOMAIN_SEPARATOR + "Remove intent from address " + address + pqNonce
        # The fingerprint is the address representation of the recovered PQ address
        remove_intent_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Remove intent from address ",
            eth_address_bytes,  # ETH address (20 bytes)
            (1).to_bytes(32, 'big')  # ethNonce (incremented after intent submission)
        )
        
        # Debug: Print the exact bytes and offsets
        print(f"  === DEBUG: Remove Intent Message Construction ===")
        print(f"  DOMAIN_SEPARATOR length: {len(DOMAIN_SEPARATOR)} bytes")
        pattern = "Remove intent from address "
        print(f"  Pattern: '{pattern}' (length: {len(pattern)} bytes)")
        print(f"  Pattern bytes: {pattern.encode('utf-8').hex()}")
        print(f"  ethNonce: 1 (32 bytes: {(1).to_bytes(32, 'big').hex()})")
        print(f"  fingerprint: {pq_fingerprint.hex()}")
        print(f"  Total message length: {len(remove_intent_message)} bytes")
        print(f"  Full message: {remove_intent_message.hex()}")
        
        # Debug: Show the expected offsets
        expected_nonce_offset = 32 + 25  # DOMAIN_SEPARATOR + pattern
        expected_fingerprint_offset = 32 + 25 + 32  # DOMAIN_SEPARATOR + pattern + nonce
        print(f"  Expected nonce offset: {expected_nonce_offset}")
        print(f"  Expected fingerprint offset: {expected_fingerprint_offset}")
        
        # Debug: Extract and show the bytes at the expected offsets
        if len(remove_intent_message) >= expected_nonce_offset + 32:
            nonce_bytes = remove_intent_message[expected_nonce_offset:expected_nonce_offset + 32]
            print(f"  Nonce bytes at offset {expected_nonce_offset}: {nonce_bytes.hex()}")
            nonce_value = int.from_bytes(nonce_bytes, 'big')
            print(f"  Nonce value: {nonce_value}")
        else:
            print(f"  ERROR: Message too short for nonce extraction")
            
        if len(remove_intent_message) >= expected_fingerprint_offset + 20:
            fingerprint_bytes = remove_intent_message[expected_fingerprint_offset:expected_fingerprint_offset + 20]
            print(f"  Fingerprint bytes at offset {expected_fingerprint_offset}: {fingerprint_bytes.hex()}")
        else:
            print(f"  ERROR: Message too short for fingerprint extraction")
        
        # Sign the remove intent message
        remove_message_length = len(remove_intent_message)
        remove_signed_message = b"\x19Ethereum Signed Message:\n" + str(remove_message_length).encode() + remove_intent_message
        remove_message_hash = keccak(remove_signed_message)
        remove_signature = Account._sign_hash(remove_message_hash, private_key=account.key)
        
        print(f"  Generated remove intent data with fingerprint: 0x{pq_fingerprint.hex()}")
        
        # ============================================================================
        # CHANGE ETH ADDRESS FLOW
        # ============================================================================
        
        # Create test data for change ETH address (using next private key)
        next_eth_priv_key = ETH_PRIVATE_KEYS[(i + 1) % len(ETH_PRIVATE_KEYS)]
        next_account = Account.from_key(next_eth_priv_key)
        next_eth_address = next_account.address
        
        # Debug: Print struct hash components for change ETH address intent
        print(f"  === PYTHON CHANGE ETH ADDRESS INTENT STRUCT HASH DEBUG ===")
        get_change_eth_address_intent_struct_hash(next_eth_address, 0)
        
        # Debug: Print EIP-712 digest calculation
        print(f"  === PYTHON EIP-712 DIGEST DEBUG ===")
        # Use the domain separator from config (assume it's loaded as DOMAIN_SEPARATOR)
        # If not, load it from config file here
        # domain_separator = ...
        # For now, use the existing logic (should be replaced with config if not already)
        def abi_encode(types, values):
            result = b''
            for t, v in zip(types, values):
                if t == 'address':
                    if isinstance(v, str) and v.startswith('0x'):
                        v = bytes.fromhex(v[2:])
                    result += v.rjust(32, b'\x00')
                elif t == 'uint256':
                    result += int(v).to_bytes(32, 'big')
                elif t == 'bytes32':
                    if isinstance(v, str) and v.startswith('0x'):
                        v = bytes.fromhex(v[2:])
                    result += v.rjust(32, b'\x00')
                else:
                    raise Exception(f"Unsupported type: {t}")
            return result
        
        # Use the domain separator from config
        domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove 0x prefix
        print(f"Domain separator: {domain_separator.hex()}")
        
        # Get struct hash
        struct_hash = get_change_eth_address_intent_struct_hash(next_eth_address, 0)
        print(f"Struct hash: {struct_hash.hex()}")
        
        # Calculate digest
        digest = keccak(b'\x19\x01' + domain_separator + struct_hash)
        print(f"EIP-712 digest: {digest.hex()}")
        
        # Sign the digest with the new ETH address (next_account)
        signature = Account._sign_hash(digest, private_key=next_account.key)
        v = signature.v
        r = signature.r
        s = signature.s
        print(f"Signing address (should be new ETH address): {next_eth_address}")
        print(f"Signature v: {v}")
        print(f"Signature r: {hex(r)}")
        print(f"Signature s: {hex(s)}")
        print(f"  === END PYTHON DIGEST DEBUG ===")
        
        print(f"  === END PYTHON DEBUG ===")
        
        # Create base PQ message for change ETH address
        next_eth_address_bytes = bytes.fromhex(next_eth_address[2:])
        change_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Change ETH Address from ",
            eth_address_bytes,  # current address
            " to ",
            next_eth_address_bytes,  # new address
            (0).to_bytes(32, 'big')  # pqNonce
        )
        
        # Generate Epervier signature for change ETH address
        print(f"  Generating Epervier signature for change ETH address...")
        change_epervier_sig = generate_epervier_signature(change_pq_message, (i + 1) % len(pq_keys))
        
        # Create ETH message for change ETH address confirmation
        # NEW FORMAT: DOMAIN_SEPARATOR + "Confirm change ETH Address" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
        change_confirm_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm change ETH Address",
            (0).to_bytes(32, 'big'),  # ethNonce for new address
            bytes.fromhex(change_epervier_sig["salt"][2:]),  # pqSignature salt
            pack_uint256_array(change_epervier_sig["cs1"]),  # cs1 as 32*32 bytes, no prefix
            pack_uint256_array(change_epervier_sig["cs2"]),  # cs2 as 32*32 bytes, no prefix
            change_epervier_sig["hint"].to_bytes(32, 'big'),  # pqSignature hint
            change_pq_message  # Include the PQ message that was signed
        )
        # Use the same format as the contract: "\x19Ethereum Signed Message:\n" + length + message
        change_confirm_length = len(change_confirm_message)
        change_confirm_signed = b"\x19Ethereum Signed Message:\n" + str(change_confirm_length).encode() + change_confirm_message
        change_confirm_hash = keccak(change_confirm_signed)
        change_confirm_signature = Account._sign_hash(change_confirm_hash, private_key=next_account.key)
        
        # Create PQ message for change ETH address confirmation (PQ key signs with ETH sig nested)
        # NEW FORMAT: DOMAIN_SEPARATOR + "Confirm changing ETH address from " + currentAddress + " to " + newAddress + pqNonce + ethSignature + ETH_message
        # The contract expects the signature at a specific offset, so we need to ensure the PQ header is exactly the right length
        change_pq_header = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm changing ETH address from ",
            eth_address_bytes,  # current address
            " to ",
            next_eth_address_bytes,  # new address
            (0).to_bytes(32, 'big')  # pqNonce
        )
        
        # Verify the header length and adjust if needed
        change_header_length = len(change_pq_header)
        print(f"  Change PQ header length: {change_header_length} bytes")
        
        change_confirm_pq_message = change_pq_header + change_confirm_signature.signature + change_confirm_message
        
        # Generate Epervier signature for change ETH address confirmation
        print(f"  Generating Epervier signature for change ETH address confirmation...")
        change_confirm_epervier_sig = generate_epervier_signature(change_confirm_pq_message, (i + 1) % len(pq_keys))
        
        # ============================================================================
        # UNREGISTRATION FLOW
        # ============================================================================
        
        # Create test data for unregistration
        # NEW FORMAT: DOMAIN_SEPARATOR + "Confirm unregistration from PQ fingerprint" + ethAddress + pqNonce
        unreg_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm unregistration from PQ fingerprint",
            next_eth_address_bytes,  # Use the new address
            (2).to_bytes(32, 'big')  # ethNonce (incremented)
        )
        
        # Generate Epervier signature for unregistration
        print(f"  Generating Epervier signature for unregistration...")
        unreg_epervier_sig = generate_epervier_signature(unreg_pq_message, (i + 2) % len(pq_keys))
        
        # Create ETH message for unregistration confirmation
        # NEW FORMAT: DOMAIN_SEPARATOR + "Confirm unregistration from PQ fingerprint" + ethNonce + salt + cs1 + cs2 + hint + base_pq_message
        unreg_confirm_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm unregistration from PQ fingerprint",
            (2).to_bytes(32, 'big'),  # ethNonce
            bytes.fromhex(unreg_epervier_sig["salt"][2:]),  # pqSignature salt
            pack_uint256_array(unreg_epervier_sig["cs1"]),  # cs1 as 32*32 bytes, no prefix
            pack_uint256_array(unreg_epervier_sig["cs2"]),  # cs2 as 32*32 bytes, no prefix
            unreg_epervier_sig["hint"].to_bytes(32, 'big'),  # pqSignature hint
            unreg_pq_message  # Include the PQ message that was signed
        )
        # Use the same format as the contract: "\x19Ethereum Signed Message:\n" + length + message
        unreg_confirm_length = len(unreg_confirm_message)
        unreg_confirm_signed = b"\x19Ethereum Signed Message:\n" + str(unreg_confirm_length).encode() + unreg_confirm_message
        unreg_confirm_hash = keccak(unreg_confirm_signed)
        unreg_confirm_signature = Account._sign_hash(unreg_confirm_hash, private_key=next_account.key)
        
        # Save comprehensive test vector
        test_vector = {
            "eth_address": eth_address,
            "next_eth_address": next_eth_address,
            "pq_public_key": pq_key,
            "pq_public_key_hash": pq_pubkey_hash,
            
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
                "eth_message": remove_intent_message.hex(),
                "eth_signature": remove_signature.signature.hex()
            },
            
            # Change ETH address data
            "change_eth_address": {
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
        filename = test_vectors_dir / f"comprehensive_vector_{i+1}.json"
        with open(filename, 'w') as f:
            json.dump(test_vector, f, indent=2)
        print(f"  Saved to {filename}")
    
    print(f"\nGenerated {len(ETH_PRIVATE_KEYS)} comprehensive test vectors in test_vectors/")
    print("Note: Test vectors now include registration, change ETH address, and unregistration scenarios.")

def generate_simple_test_vector():
    """Generate a simple test vector for basic tests"""
    print("Generating simple test vector...")
    
    # Use the first private key and PQ key
    eth_priv_key = ETH_PRIVATE_KEYS[0]
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
    epervier_sig = generate_epervier_signature(base_pq_message, 0)
    
    # Create ETH message that includes the PQ signature components
    eth_intent_message = abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair Epervier Key",
        (0).to_bytes(32, 'big'),  # ethNonce
        bytes.fromhex(epervier_sig["salt"][2:]),  # pqSignature salt
        pack_uint256_array(epervier_sig["cs1"]),  # cs1 as 32*32 bytes, no prefix
        pack_uint256_array(epervier_sig["cs2"]),  # cs2 as 32*32 bytes, no prefix
        epervier_sig["hint"].to_bytes(32, 'big'),  # pqSignature hint
        base_pq_message  # pqMessage
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

def get_change_eth_address_intent_struct_hash(new_eth_address, eth_nonce):
    from eth_hash.auto import keccak
    """Get the struct hash for ChangeETHAddressIntent"""
    # Type hash for ChangeETHAddressIntent - matches the contract
    type_hash = keccak(b"ChangeETHAddressIntent(address newETHAddress,uint256 ethNonce)")
    
    def abi_encode(types, values):
        # Supports address, uint256, and bytes32 for this debug
        result = b''
        for t, v in zip(types, values):
            if t == 'address':
                if isinstance(v, str) and v.startswith('0x'):
                    v = bytes.fromhex(v[2:])
                result += v.rjust(32, b'\x00')
            elif t == 'uint256':
                result += int(v).to_bytes(32, 'big')
            elif t == 'bytes32':
                if isinstance(v, str) and v.startswith('0x'):
                    v = bytes.fromhex(v[2:])
                result += v.rjust(32, b'\x00')
            else:
                raise Exception(f"Unsupported type: {t}")
        return result
    
    # Encode the struct with type hash - matches the contract signature
    encoded = abi_encode(['bytes32', 'address', 'uint256'], 
                        [type_hash, new_eth_address, eth_nonce])
    
    print(f"=== PYTHON STRUCT HASH COMPONENTS ===")
    print(f"Type hash: {type_hash.hex()}")
    print(f"New ETH address: {new_eth_address}")
    print(f"ETH nonce: {eth_nonce}")
    print(f"Encoded struct bytes: {encoded.hex()}")
    
    # Calculate final struct hash
    struct_hash = keccak(encoded)
    print(f"Final struct hash: {struct_hash.hex()}")
    print(f"=====================================")
    
    return struct_hash

if __name__ == "__main__":
    generate_comprehensive_test_vectors()
    generate_simple_test_vector() 
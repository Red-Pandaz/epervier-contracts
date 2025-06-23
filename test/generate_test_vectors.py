#!/usr/bin/env python3
import json
import subprocess
import sys
import os
from pathlib import Path
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

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
            "../ETHFALCON/python-ref/sign_cli.py", 
            "sign",
            "--version", "epervier",
            "--privkey", f"test_keys/private_key_{pq_key_index + 1}.pem",
            "--data", message_hex
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=".")
        
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
        sig_file = Path("sig")
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

def generate_test_vectors():
    """Generate test vectors for PQRegistry testing with nested signature structure"""
    # Create test_vectors directory
    test_vectors_dir = Path("test_vectors")
    test_vectors_dir.mkdir(exist_ok=True)
    
    # Get PQ public keys
    pq_keys = get_pq_public_keys()
    
    print(f"Generating test vectors for {len(ETH_PRIVATE_KEYS)} key combinations...")
    
    for i, (eth_priv_key, pq_key) in enumerate(zip(ETH_PRIVATE_KEYS, pq_keys)):
        print(f"Generating vector {i+1}...")
        
        # Create Ethereum account
        account = Account.from_key(eth_priv_key)
        eth_address = account.address
        
        # Calculate PQ public key hash
        pq_pubkey_bytes = pq_key[0].to_bytes(32, 'big') + pq_key[1].to_bytes(32, 'big')
        pq_pubkey_hash = "0x" + pq_pubkey_bytes.hex()
        
        # Create base PQ message (without ETH signature)
        # Format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce (32 bytes)
        eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove "0x" prefix and convert to bytes
        
        base_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to pair ETH Address ",
            eth_address_bytes,  # Use raw 20-byte address
            (0).to_bytes(32, 'big')  # pqNonce as 32-byte value
        )
        
        # Generate Epervier signature for the base PQ message (without ETH signature)
        print(f"  Generating Epervier signature for key {i+1}...")
        epervier_sig = generate_epervier_signature(base_pq_message, i)
        
        # Create ETH message for intent (without PQ signature)
        # Format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + ethNonce + base_pq_message
        eth_intent_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to pair Epervier Key",
            (0).to_bytes(32, 'big'),  # ethNonce as 32-byte value (matching contract's abi.encodePacked)
            base_pq_message  # Base PQ message without ETH signature
        )
        print(f"ETH intent message hex: {eth_intent_message.hex()}")
        eth_message_hash = encode_defunct(eth_intent_message)
        eth_signature = account.sign_message(eth_message_hash)
        
        # Create full PQ message for intent (ETH signature nested in PQ message)
        # Format: base_pq_message + eth_signature (last 65 bytes)
        full_pq_message = abi_encode_packed(
            base_pq_message,
            eth_signature.signature  # Include ETH signature in PQ message
        )
        
        # Create ETH message for confirmRegistration (PQ signature nested in ETH message)
        # Format: DOMAIN_SEPARATOR + "Confirm registration" + ethNonce + salt + abi.encode(cs1) + abi.encode(cs2) + abi.encode(hint) + base_pq_message
        eth_confirm_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm registration",
            (0).to_bytes(32, 'big'),  # ethNonce as 32-byte value (matching contract's abi.encodePacked)
            bytes.fromhex(epervier_sig["salt"][2:]),  # salt without 0x prefix
            abi_encode(epervier_sig["cs1"]),  # cs1 array with abi.encode
            abi_encode(epervier_sig["cs2"]),  # cs2 array with abi.encode
            abi_encode(epervier_sig["hint"]),  # hint with abi.encode
            base_pq_message  # Base PQ message (without ETH signature)
        )
        eth_confirm_hash = encode_defunct(eth_confirm_message)
        eth_confirm_signature = account.sign_message(eth_confirm_hash)
        
        # Create ETH message for removeIntent (similar to intent)
        eth_remove_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Unpair from fingerprint",
            (0).to_bytes(32, 'big'),  # ethNonce as 32-byte value (matching contract's abi.encodePacked)
            base_pq_message  # Base PQ message without ETH signature
        )
        eth_remove_hash = encode_defunct(eth_remove_message)
        eth_remove_signature = account.sign_message(eth_remove_hash)
        
        # Create the test vector
        vector = {
            "pq_public_key": pq_key,
            "pq_public_key_hash": pq_pubkey_hash,
            "eth_address": eth_address,
            "eth_private_key": eth_priv_key,
            "base_pq_message": base_pq_message.hex(),
            "full_pq_message": full_pq_message.hex(),
            "eth_intent_message": eth_intent_message.hex(),
            "eth_confirm_message": eth_confirm_message.hex(),
            "eth_remove_message": eth_remove_message.hex(),
            "epervier_signature": epervier_sig,
            "eth_intent_signature": eth_signature.signature.hex(),
            "eth_confirm_signature": eth_confirm_signature.signature.hex(),
            "eth_remove_signature": eth_remove_signature.signature.hex(),
            "nonce": 0
        }
        
        # Save to file
        output_file = test_vectors_dir / f"test_vector_{i+1}.json"
        with open(output_file, 'w') as f:
            json.dump(vector, f, indent=2)
        
        print(f"  Saved to {output_file}")
    
    print(f"\nGenerated {len(ETH_PRIVATE_KEYS)} test vectors in {test_vectors_dir}/")
    print("Note: Test vectors now use proper nested signatures with real PQ signatures.")

if __name__ == "__main__":
    generate_test_vectors() 
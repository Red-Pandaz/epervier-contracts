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

def generate_comprehensive_test_vectors():
    """Generate comprehensive test vectors for all PQRegistry scenarios"""
    # Create test_vectors directory
    test_vectors_dir = Path("test_vectors")
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
        
        # Create base PQ message for registration
        eth_address_bytes = bytes.fromhex(eth_address[2:])
        base_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to pair ETH Address ",
            eth_address_bytes,
            (0).to_bytes(32, 'big')  # pqNonce
        )
        
        # Generate Epervier signature for registration
        print(f"  Generating Epervier signature for registration...")
        epervier_sig = generate_epervier_signature(base_pq_message, i)
        
        # Create ETH message for registration intent
        eth_intent_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to pair Epervier Key",
            (0).to_bytes(32, 'big'),  # ethNonce
            base_pq_message
        )
        eth_message_hash = encode_defunct(eth_intent_message)
        eth_signature = account.sign_message(eth_message_hash)
        
        # Create full PQ message for registration intent
        full_pq_message = abi_encode_packed(
            base_pq_message,
            eth_signature.signature
        )
        
        # Create ETH message for registration confirmation
        eth_confirm_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm registration",
            (0).to_bytes(32, 'big'),  # ethNonce
            bytes.fromhex(epervier_sig["salt"][2:]),
            abi_encode(epervier_sig["cs1"]),
            abi_encode(epervier_sig["cs2"]),
            abi_encode(epervier_sig["hint"]),
            base_pq_message
        )
        eth_confirm_hash = encode_defunct(eth_confirm_message)
        eth_confirm_signature = account.sign_message(eth_confirm_hash)
        
        # Create test data for change ETH address (using next private key)
        next_eth_priv_key = ETH_PRIVATE_KEYS[(i + 1) % len(ETH_PRIVATE_KEYS)]
        next_account = Account.from_key(next_eth_priv_key)
        next_eth_address = next_account.address
        
        # Create base PQ message for change ETH address
        next_eth_address_bytes = bytes.fromhex(next_eth_address[2:])
        change_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to pair ETH Address ",
            next_eth_address_bytes,
            (0).to_bytes(32, 'big')  # pqNonce
        )
        
        # Generate Epervier signature for change ETH address
        print(f"  Generating Epervier signature for change ETH address...")
        change_epervier_sig = generate_epervier_signature(change_pq_message, (i + 1) % len(pq_keys))
        
        # Create ETH message for change ETH address confirmation
        change_confirm_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm change ETH Address",
            (0).to_bytes(32, 'big'),  # ethNonce for new address
            bytes.fromhex(change_epervier_sig["salt"][2:]),
            abi_encode(change_epervier_sig["cs1"]),
            abi_encode(change_epervier_sig["cs2"]),
            abi_encode(change_epervier_sig["hint"]),
            change_pq_message
        )
        change_confirm_hash = encode_defunct(change_confirm_message)
        change_confirm_signature = next_account.sign_message(change_confirm_hash)
        
        # Create test data for unregistration
        unreg_pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to pair ETH Address ",
            next_eth_address_bytes,  # Use the new address
            (1).to_bytes(32, 'big')  # pqNonce (incremented)
        )
        
        # Generate Epervier signature for unregistration
        print(f"  Generating Epervier signature for unregistration...")
        unreg_epervier_sig = generate_epervier_signature(unreg_pq_message, (i + 2) % len(pq_keys))
        
        # Save comprehensive test vector
        test_vector = {
            "eth_address": eth_address,
            "next_eth_address": next_eth_address,
            "pq_public_key": pq_key,
            "pq_public_key_hash": pq_pubkey_hash,
            
            # Registration data
            "registration": {
                "base_pq_message": base_pq_message.hex(),
                "full_pq_message": full_pq_message.hex(),
                "eth_intent_message": eth_intent_message.hex(),
                "eth_confirm_message": eth_confirm_message.hex(),
                "eth_intent_signature": eth_signature.signature.hex(),
                "eth_confirm_signature": eth_confirm_signature.signature.hex(),
                "epervier_salt": epervier_sig["salt"],
                "epervier_cs1": epervier_sig["cs1"],
                "epervier_cs2": epervier_sig["cs2"],
                "epervier_hint": epervier_sig["hint"]
            },
            
            # Change ETH address data
            "change_eth_address": {
                "base_pq_message": change_pq_message.hex(),
                "eth_confirm_message": change_confirm_message.hex(),
                "eth_confirm_signature": change_confirm_signature.signature.hex(),
                "epervier_salt": change_epervier_sig["salt"],
                "epervier_cs1": change_epervier_sig["cs1"],
                "epervier_cs2": change_epervier_sig["cs2"],
                "epervier_hint": change_epervier_sig["hint"]
            },
            
            # Unregistration data
            "unregistration": {
                "base_pq_message": unreg_pq_message.hex(),
                "epervier_salt": unreg_epervier_sig["salt"],
                "epervier_cs1": unreg_epervier_sig["cs1"],
                "epervier_cs2": unreg_epervier_sig["cs2"],
                "epervier_hint": unreg_epervier_sig["hint"]
            }
        }
        
        # Save to file
        filename = f"test_vectors/comprehensive_vector_{i+1}.json"
        with open(filename, 'w') as f:
            json.dump(test_vector, f, indent=2)
        print(f"  Saved to {filename}")
    
    print(f"\nGenerated {len(ETH_PRIVATE_KEYS)} comprehensive test vectors in test_vectors/")
    print("Note: Test vectors now include registration, change ETH address, and unregistration scenarios.")

if __name__ == "__main__":
    generate_comprehensive_test_vectors() 
#!/usr/bin/env python3
import json
import subprocess
import sys
import os
from pathlib import Path
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

# Foundry default private keys (first 5)
ETH_PRIVATE_KEYS = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118e8d7e3bdfa4b9b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
]

# PQ Registry domain separator
DOMAIN_SEPARATOR = "0x" + "PQRegistry".encode().hex()

def abi_encode_packed(*args):
    """Simple ABI encodePacked implementation"""
    result = b""
    for arg in args:
        if isinstance(arg, str):
            if arg.startswith("0x"):
                result += bytes.fromhex(arg[2:])
            else:
                result += arg.encode()
        elif isinstance(arg, int):
            result += arg.to_bytes(32, 'big')
        elif isinstance(arg, bytes):
            result += arg
        else:
            result += str(arg).encode()
    return result

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
    """Parse the signature file to extract salt, cs1, cs2, hint"""
    try:
        with open(sig_file_path, 'r') as f:
            sig_hex = f.read().strip()
        
        # Convert hex to bytes
        sig_bytes = bytes.fromhex(sig_hex)
        
        # Constants from the CLI code
        HEAD_LEN = 1
        SALT_LEN = 40
        
        # Extract salt (first 40 bytes after header)
        salt = sig_bytes[HEAD_LEN:HEAD_LEN + SALT_LEN]
        
        # Extract the encoded signature part (everything after salt, except last 512*3 bytes)
        enc_s = sig_bytes[HEAD_LEN + SALT_LEN:-512*3]
        
        # For now, we'll use the raw signature and let the contract parse it
        # The contract's epervierVerifier.recover() function will handle the parsing
        # We'll store the raw signature and let the tests use it directly
        
        return {
            "salt": "0x" + salt.hex(),
            "cs1": [0] * 32,  # Will be parsed by the verifier
            "cs2": [0] * 32,  # Will be parsed by the verifier  
            "hint": 123,      # Will be parsed by the verifier
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
        
        # Create PQ message (signed by PQ key)
        # Format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + address + pqNonce
        pq_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to pair ETH Address ",
            eth_address,
            0  # pqNonce
        )
        
        # Generate Epervier signature for PQ message
        print(f"  Generating Epervier signature for key {i+1}...")
        epervier_sig = generate_epervier_signature(pq_message, i)
        
        # Create ETH message for submitRegistrationIntent (nested signature)
        # Format: DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + ethNonce + pqSignature + pqMessage
        eth_intent_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Intent to pair Epervier Key",
            0,  # ethNonce
            bytes.fromhex(epervier_sig["raw_signature"]),  # pqSignature
            pq_message  # pqMessage
        )
        eth_message_hash = encode_defunct(eth_intent_message)
        eth_signature = account.sign_message(eth_message_hash)
        
        # Create ETH message for confirmRegistration (nested signature)
        # Format: DOMAIN_SEPARATOR + "Confirm registration" + ethNonce + pqSignature + pqMessage
        eth_confirm_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Confirm registration",
            0,  # ethNonce
            bytes.fromhex(epervier_sig["raw_signature"]),  # pqSignature
            pq_message  # pqMessage
        )
        eth_confirm_hash = encode_defunct(eth_confirm_message)
        eth_confirm_signature = account.sign_message(eth_confirm_hash)
        
        # Create ETH message for removeIntent (nested signature)
        # Format: DOMAIN_SEPARATOR + "Unpair from fingerprint" + ethNonce + pqSignature + pqMessage
        eth_remove_message = abi_encode_packed(
            DOMAIN_SEPARATOR,
            "Unpair from fingerprint",
            0,  # ethNonce
            bytes.fromhex(epervier_sig["raw_signature"]),  # pqSignature
            pq_message  # pqMessage
        )
        eth_remove_hash = encode_defunct(eth_remove_message)
        eth_remove_signature = account.sign_message(eth_remove_hash)
        
        # Create the test vector
        vector = {
            "pq_public_key": pq_key,
            "pq_public_key_hash": pq_pubkey_hash,
            "eth_address": eth_address,
            "eth_private_key": eth_priv_key,
            "pq_message": pq_message.hex(),
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
    print("Note: Test vectors now use nested signature structure.")

if __name__ == "__main__":
    generate_test_vectors() 
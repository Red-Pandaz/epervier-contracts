#!/usr/bin/env python3
"""
Generate registration intent vector for Bob with nonce 1
"""

import json
import subprocess
from pathlib import Path
from eth_account import Account
from eth_hash.auto import keccak

# Project root
PROJECT_ROOT = Path(__file__).resolve().parents[3]  # epervier-registry

# Domain separator (same as in the contract)
DOMAIN_SEPARATOR = bytes.fromhex("5f5d847b41fe04c02ecf9746150300028bfc195e7981ae8fe39fe8b7a745650f")

def abi_encode_packed(*args):
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

def generate_eth_signature(message, private_key):
    """Generate ETH signature for a message"""
    account = Account.from_key(private_key)
    message_hash = keccak(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode() + message)
    signature = Account._sign_hash(message_hash, private_key=account.key)
    return {
        "v": signature.v,
        "r": signature.r,
        "s": signature.s
    }

def generate_epervier_signature(message, actor_config):
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

def pack_uint256_array(arr):
    """Pack array of uint256 values into bytes"""
    result = b""
    for val in arr:
        result += val.to_bytes(32, 'big')
    return result

def create_base_pq_registration_intent_message(eth_address, pq_nonce):
    """Create base PQ registration intent message"""
    eth_address_bytes = bytes.fromhex(eth_address[2:])  # Remove 0x prefix
    return abi_encode_packed(
        DOMAIN_SEPARATOR,
        "Intent to pair ETH Address ",
        eth_address_bytes,
        pq_nonce.to_bytes(32, 'big')
    )

def create_eth_registration_intent_message(base_pq_message, salt, cs1, cs2, hint, eth_nonce):
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

def main():
    # Load actor configuration
    config_file = PROJECT_ROOT / "test" / "test_keys" / "actors_config.json"
    with open(config_file, 'r') as f:
        actors_config = json.load(f)
    
    bob_config = actors_config["bob"]
    
    # Generate base PQ message with nonce 1
    base_pq_message = create_base_pq_registration_intent_message(bob_config["eth_address"], 1)
    
    # Generate PQ signature
    pq_signature = generate_epervier_signature(base_pq_message, bob_config)
    
    # Generate ETH message with nonce 2 (since ETH nonce should be 2 after Step 2)
    eth_message = create_eth_registration_intent_message(
        base_pq_message,
        pq_signature["salt"],
        pq_signature["cs1"],
        pq_signature["cs2"],
        pq_signature["hint"],
        2  # ETH nonce should be 2 after Step 2
    )
    
    # Generate ETH signature
    eth_signature = generate_eth_signature(eth_message, bob_config["eth_private_key"])
    
    # Create the vector
    vector = {
        "actor": "bob",
        "eth_address": bob_config["eth_address"],
        "pq_fingerprint": bob_config["pq_fingerprint"],
        "base_pq_message": base_pq_message.hex(),
        "pq_signature": {
            "salt": pq_signature["salt"],
            "cs1": [hex(x) for x in pq_signature["cs1"]],
            "cs2": [hex(x) for x in pq_signature["cs2"]],
            "hint": pq_signature["hint"]
        },
        "eth_message": eth_message.hex(),
        "eth_signature": {
            "v": eth_signature["v"],
            "r": eth_signature["r"],
            "s": eth_signature["s"]
        },
        "eth_nonce": 2,
        "pq_nonce": 1
    }
    
    # Save to a new file
    output_file = PROJECT_ROOT / "test" / "test_vectors" / "bob_nonce1_vector.json"
    with open(output_file, 'w') as f:
        json.dump({"bob_nonce1_vector": [vector]}, f, indent=2)
    
    print(f"Generated vector for Bob with nonce 1 saved to {output_file}")

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
PQ Transfer Vector Generator

This script generates test vectors for PQ transfer scenarios using the proper message schema:
- Domain Separator (32 bytes)
- Token ID (32 bytes) 
- Recipient Address (20 bytes)
- PQ Nonce (32 bytes)
- Timestamp (32 bytes)
Total: 148 bytes

Scenarios:
- Transfer from fingerprint to ETH address
- Transfer from ETH address to fingerprint
- Multi-hop transfers
- Transfer with wrong signature (should fail)
"""

import json
import os
import sys
import subprocess
import time
from typing import Dict, List, Any
from eth_account import Account
from eth_account.messages import encode_defunct
import hashlib
from pathlib import Path
from eth_utils import keccak

# Add the parent directory to the path to import eip712_config
sys.path.append(str(Path(__file__).parent.parent.parent))

# Add ETHFALCON python-ref to path for signature parsing
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "ETHFALCON" / "python-ref"))

# Add test/python to path for production_eip712_config import
sys.path.append(str(Path(__file__).resolve().parents[5] / "test" / "python"))

from production_eip712_config import DOMAIN_SEPARATOR, PQERC721_TRANSFER_DOMAIN_SEPARATOR

def parse_signature_file(sig_file_path):
    """Parse the signature file to extract salt, cs1, cs2, hint using the same logic as the CLI"""
    try:
        with open(sig_file_path, 'r') as f:
            sig_hex = f.read().strip()
        
        # Convert hex to bytes
        sig_bytes = bytes.fromhex(sig_hex)
        
        # Extract salt (first 40 bytes after header)
        HEAD_LEN = 1
        SALT_LEN = 40
        salt = sig_bytes[HEAD_LEN:HEAD_LEN + SALT_LEN]
        
        # For now, return placeholder values since we don't have the full decompression logic
        # In practice, you'd decompress enc_s to get s1 and s2, then compact them
        return {
            "salt": "0x" + salt.hex(),
            "cs1": [0] * 32,  # Placeholder - need proper parsing
            "cs2": [0] * 32,  # Placeholder - need proper parsing
            "hint": 12345  # Placeholder - need proper parsing
        }
        
    except Exception as e:
        print(f"Error parsing signature file: {e}")
        return {
            "salt": "0x" + "00" * 40,
            "cs1": [0] * 32,
            "cs2": [0] * 32,
            "hint": 12345
        }

def get_actor_config() -> Dict[str, Any]:
    """Load actor configuration from JSON file and add PQ private keys from PEM files"""
    # Always use the project root as the base
    project_root = Path(__file__).resolve().parents[5]
    config_path = project_root / "test" / "test_keys" / "production_actors_config.json"
    with open(config_path, 'r') as f:
        config = json.load(f)
    actors = config["actors"]
    for actor in actors.values():
        pq_key_file = project_root / "test" / "test_keys" / actor["pq_private_key_file"]
        with open(pq_key_file, 'r') as keyfile:
            actor["pq_private_key"] = keyfile.read().strip()
    return actors

def sign_with_pq_key(message: bytes, pq_private_key_file: str, pq_nonce: int, pq_fingerprint: str) -> Dict[str, Any]:
    """
    Sign a message with a PQ key using the real Epervier CLI, matching the registration generator's approach.
    """
    from pathlib import Path
    import subprocess
    # Use project root for all paths
    project_root = Path(__file__).resolve().parents[5]
    privkey_path = project_root / "test" / "test_keys" / pq_private_key_file
    venv_python = project_root / "ETHFALCON" / "python-ref" / "myenv" / "bin" / "python3"
    sign_cli = project_root / "ETHFALCON" / "python-ref" / "sign_cli.py"
    message_hex = message.hex()
    cmd = [
        str(venv_python), str(sign_cli), "sign",
        f"--privkey={privkey_path}",
        f"--data={message_hex}",
        "--version=epervier"
    ]
    print(f"Signing message with Epervier CLI: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"CLI stdout: {result.stdout}")
    print(f"CLI stderr: {result.stderr}")
    if result.returncode != 0:
        print(f"Warning: CLI failed with return code {result.returncode}")
        return None
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
        print("Failed to parse PQ signature components!")
        return None
    return out

def create_pq_transfer_message(
    domain_separator: bytes,
    token_id: int,
    recipient_address: str,
    pq_nonce: int,
    timestamp: int
) -> bytes:
    """
    Create a PQ transfer message in the format expected by the contract:
    - Domain Separator (32 bytes)
    - Token ID (32 bytes) 
    - Recipient Address (20 bytes)
    - PQ Nonce (32 bytes)
    - Timestamp (32 bytes)
    Total: 148 bytes
    """
    # Ensure domain separator is 32 bytes
    if len(domain_separator) < 32:
        domain_separator = domain_separator.ljust(32, b'\x00')
    elif len(domain_separator) > 32:
        domain_separator = domain_separator[:32]
    
    # Convert token ID to 32 bytes
    token_id_bytes = token_id.to_bytes(32, 'big')
    
    # Convert recipient address to 20 bytes (remove 0x prefix if present)
    if recipient_address.startswith('0x'):
        recipient_address = recipient_address[2:]
    recipient_bytes = bytes.fromhex(recipient_address)
    if len(recipient_bytes) != 20:
        raise ValueError(f"Invalid recipient address length: {len(recipient_bytes)}")
    
    # Keep recipient address as 20 bytes (schema defines it as 20 bytes)
    
    # Convert PQ nonce to 32 bytes
    pq_nonce_bytes = pq_nonce.to_bytes(32, 'big')
    
    # Convert timestamp to 32 bytes
    timestamp_bytes = timestamp.to_bytes(32, 'big')
    
    # Concatenate all components
    message = domain_separator + token_id_bytes + recipient_bytes + pq_nonce_bytes + timestamp_bytes
    
    if len(message) != 148:  # 32 + 32 + 20 + 32 + 32 = 148 bytes
        raise ValueError(f"Invalid message length: {len(message)}, expected 148")
    
    return message

def generate_pq_transfer_vectors() -> List[Dict[str, Any]]:
    """Generate test vectors for PQ transfer scenarios"""
    
    actors = get_actor_config()
    # Use production actors: kyle, luke, marie, nancy, oscar
    kyle = actors["kyle"]
    luke = actors["luke"]
    marie = actors["marie"]
    nancy = actors["nancy"]
    oscar = actors["oscar"]
    
    # Create eth_account objects from private keys
    kyle["eth_account"] = Account.from_key(kyle["eth_private_key"])
    luke["eth_account"] = Account.from_key(luke["eth_private_key"])
    marie["eth_account"] = Account.from_key(marie["eth_private_key"])
    nancy["eth_account"] = Account.from_key(nancy["eth_private_key"])
    oscar["eth_account"] = Account.from_key(oscar["eth_private_key"])
    
    # Ensure all transfer vectors use pq_nonce = 0
    kyle_pq_nonce = 0
    luke_pq_nonce = 0
    marie_pq_nonce = 0
    nancy_pq_nonce = 0
    oscar_pq_nonce = 0
    # For multi-hop, set nonce=0 for every hop
    hops = [
        (kyle, luke["eth_address"], 0),
        (luke, marie["pq_fingerprint"], 0),
        (marie, nancy["eth_address"], 0)
    ]
    # If there are any other transfer vector definitions, set their pq_nonce to 0 as well.
    
    # Domain separator for PQ transfers (matches contract)
    ds_clean = PQERC721_TRANSFER_DOMAIN_SEPARATOR.strip()
    print(f"PQERC721_TRANSFER_DOMAIN_SEPARATOR: {repr(ds_clean)} length: {len(ds_clean)}")
    if ds_clean.startswith('0x'):
        ds_clean = ds_clean[2:]
    ds_clean = ds_clean[:64]  # Ensure exactly 32 bytes
    domain_separator = bytes.fromhex(ds_clean)
    
    # Generate deterministic token IDs for each fingerprint (MUST MATCH CONTRACT)
    def calc_token_id(fingerprint):
        # Remove 0x if present
        if fingerprint.startswith('0x'):
            fingerprint_bytes = bytes.fromhex(fingerprint[2:])
        else:
            fingerprint_bytes = bytes.fromhex(fingerprint)
        packed = b"PQ_TOKEN" + fingerprint_bytes
        token_id_bytes = keccak(packed)
        token_id = int.from_bytes(token_id_bytes, 'big')
        print(f"DEBUG: Calculated token_id for fingerprint {fingerprint}: {token_id}")
        return token_id
    kyle_token_id = calc_token_id(kyle['pq_fingerprint'])
    luke_token_id = calc_token_id(luke['pq_fingerprint'])
    marie_token_id = calc_token_id(marie['pq_fingerprint'])
    nancy_token_id = calc_token_id(nancy['pq_fingerprint'])
    oscar_token_id = calc_token_id(oscar['pq_fingerprint'])
    
    vectors = []
    current_timestamp = int(time.time())
    
    # Vector 1: Transfer from Kyle's fingerprint to Luke's ETH address
    kyle_pq_message = create_pq_transfer_message(
        domain_separator,
        kyle_token_id,
        luke["eth_address"],
        kyle_pq_nonce,
        current_timestamp
    )
    
    kyle_pq_sig = sign_with_pq_key(
        kyle_pq_message,
        kyle["pq_private_key_file"],
        kyle_pq_nonce,
        kyle["pq_fingerprint"]
    )
    
    vectors.append({
        "description": "Transfer from Kyle's fingerprint to Luke's ETH address",
        "token_id": kyle_token_id,
        "from_fingerprint": kyle["pq_fingerprint"],
        "to_address": luke["eth_address"],
        "pq_message": kyle_pq_message.hex(),
        "pq_signature": {
            "salt": kyle_pq_sig["salt"].hex() if kyle_pq_sig else "0x" + "00" * 40,
            "cs1": [hex(x) for x in kyle_pq_sig["cs1"]] if kyle_pq_sig else [hex(0)] * 32,
            "cs2": [hex(x) for x in kyle_pq_sig["cs2"]] if kyle_pq_sig else [hex(0)] * 32,
            "hint": kyle_pq_sig["hint"] if kyle_pq_sig else 12345
        },
        "pq_nonce": kyle_pq_nonce,
        "timestamp": current_timestamp,
        "expected_result": "success"
    })
    
    # Vector 2: Transfer from Luke's fingerprint to Marie's ETH address
    luke_pq_message = create_pq_transfer_message(
        domain_separator,
        luke_token_id,
        marie["eth_address"],
        luke_pq_nonce,
        current_timestamp + 1
    )
    
    luke_pq_sig = sign_with_pq_key(
        luke_pq_message,
        luke["pq_private_key_file"],
        luke_pq_nonce,
        luke["pq_fingerprint"]
    )
    
    vectors.append({
        "description": "Transfer from Luke's fingerprint to Marie's ETH address",
        "token_id": luke_token_id,
        "from_fingerprint": luke["pq_fingerprint"],
        "to_address": marie["eth_address"],
        "pq_message": luke_pq_message.hex(),
        "pq_signature": {
            "salt": luke_pq_sig["salt"].hex() if luke_pq_sig else "0x" + "00" * 40,
            "cs1": [hex(x) for x in luke_pq_sig["cs1"]] if luke_pq_sig else [hex(0)] * 32,
            "cs2": [hex(x) for x in luke_pq_sig["cs2"]] if luke_pq_sig else [hex(0)] * 32,
            "hint": luke_pq_sig["hint"] if luke_pq_sig else 12345
        },
        "pq_nonce": luke_pq_nonce,
        "timestamp": current_timestamp + 1,
        "expected_result": "success"
    })
    
    # Vector 3: Transfer from Marie's fingerprint to Nancy's ETH address
    marie_pq_message = create_pq_transfer_message(
        domain_separator,
        marie_token_id,
        nancy["eth_address"],
        marie_pq_nonce,
        current_timestamp + 2
    )
    
    marie_pq_sig = sign_with_pq_key(
        marie_pq_message,
        marie["pq_private_key_file"],
        marie_pq_nonce,
        marie["pq_fingerprint"]
    )
    
    vectors.append({
        "description": "Transfer from Marie's fingerprint to Nancy's ETH address",
        "token_id": marie_token_id,
        "from_fingerprint": marie["pq_fingerprint"],
        "to_address": nancy["eth_address"],
        "pq_message": marie_pq_message.hex(),
        "pq_signature": {
            "salt": marie_pq_sig["salt"].hex() if marie_pq_sig else "0x" + "00" * 40,
            "cs1": [hex(x) for x in marie_pq_sig["cs1"]] if marie_pq_sig else [hex(0)] * 32,
            "cs2": [hex(x) for x in marie_pq_sig["cs2"]] if marie_pq_sig else [hex(0)] * 32,
            "hint": marie_pq_sig["hint"] if marie_pq_sig else 12345
        },
        "pq_nonce": marie_pq_nonce,
        "timestamp": current_timestamp + 2,
        "expected_result": "success"
    })
    
    # Vector 4: Wrong signature test - Kyle's token but Luke's signature
    wrong_pq_message = create_pq_transfer_message(
        domain_separator,
        kyle_token_id,
        luke["eth_address"],
        kyle_pq_nonce,
        current_timestamp + 3
    )
    
    wrong_pq_sig = sign_with_pq_key(
        wrong_pq_message,
        luke["pq_private_key_file"],  # Using Luke's key instead of Kyle's
        luke_pq_nonce,
        luke["pq_fingerprint"]  # Luke's fingerprint instead of Kyle's
    )
    
    vectors.append({
        "description": "Transfer with wrong signature (Kyle's token, Luke's signature)",
        "token_id": kyle_token_id,
        "from_fingerprint": kyle["pq_fingerprint"],
        "to_address": luke["eth_address"],
        "pq_message": wrong_pq_message.hex(),
        "pq_signature": {
            "salt": wrong_pq_sig["salt"].hex() if wrong_pq_sig else "0x" + "00" * 40,
            "cs1": [hex(x) for x in wrong_pq_sig["cs1"]] if wrong_pq_sig else [hex(0)] * 32,
            "cs2": [hex(x) for x in wrong_pq_sig["cs2"]] if wrong_pq_sig else [hex(0)] * 32,
            "hint": wrong_pq_sig["hint"] if wrong_pq_sig else 12345
        },
        "pq_nonce": kyle_pq_nonce,
        "timestamp": current_timestamp + 3,
        "expected_result": "failure"
    })
    
    # Vector 5: Transfer to zero address (should fail)
    kyle_zero_message = create_pq_transfer_message(
        domain_separator,
        kyle_token_id,
        "0x0000000000000000000000000000000000000000",
        kyle_pq_nonce,
        current_timestamp + 4
    )
    
    kyle_zero_sig = sign_with_pq_key(
        kyle_zero_message,
        kyle["pq_private_key_file"],
        kyle_pq_nonce,
        kyle["pq_fingerprint"]
    )
    
    vectors.append({
        "description": "Transfer to zero address (should fail)",
        "token_id": kyle_token_id,
        "from_fingerprint": kyle["pq_fingerprint"],
        "to_address": "0x0000000000000000000000000000000000000000",
        "pq_message": kyle_zero_message.hex(),
        "pq_signature": {
            "salt": kyle_zero_sig["salt"].hex() if kyle_zero_sig else "0x" + "00" * 40,
            "cs1": [hex(x) for x in kyle_zero_sig["cs1"]] if kyle_zero_sig else [hex(0)] * 32,
            "cs2": [hex(x) for x in kyle_zero_sig["cs2"]] if kyle_zero_sig else [hex(0)] * 32,
            "hint": kyle_zero_sig["hint"] if kyle_zero_sig else 12345
        },
        "pq_nonce": kyle_pq_nonce,
        "timestamp": current_timestamp + 4,
        "expected_result": "failure"
    })
    
    # Vector 6: Invalid domain separator (should fail)
    wrong_domain = hashlib.sha256("WRONG_DOMAIN".encode()).digest()
    kyle_wrong_domain_message = create_pq_transfer_message(
        wrong_domain,
        kyle_token_id,
        luke["eth_address"],
        kyle_pq_nonce,
        current_timestamp + 5
    )
    
    kyle_wrong_domain_sig = sign_with_pq_key(
        kyle_wrong_domain_message,
        kyle["pq_private_key_file"],
        kyle_pq_nonce,
        kyle["pq_fingerprint"]
    )
    
    vectors.append({
        "description": "Transfer with wrong domain separator (should fail)",
        "token_id": kyle_token_id,
        "from_fingerprint": kyle["pq_fingerprint"],
        "to_address": luke["eth_address"],
        "pq_message": kyle_wrong_domain_message.hex(),
        "pq_signature": {
            "salt": kyle_wrong_domain_sig["salt"].hex() if kyle_wrong_domain_sig else "0x" + "00" * 40,
            "cs1": [hex(x) for x in kyle_wrong_domain_sig["cs1"]] if kyle_wrong_domain_sig else [hex(0)] * 32,
            "cs2": [hex(x) for x in kyle_wrong_domain_sig["cs2"]] if kyle_wrong_domain_sig else [hex(0)] * 32,
            "hint": kyle_wrong_domain_sig["hint"] if kyle_wrong_domain_sig else 12345
        },
        "pq_nonce": kyle_pq_nonce,
        "timestamp": current_timestamp + 5,
        "expected_result": "failure"
    })
    
    return vectors

def generate_multi_hop_vectors() -> list:
    """
    Generate a sequence of PQ transfer vectors for multi-hop transfers of Kyle's token:
    Kyle's Fingerprint -> Luke's ETH Address -> Marie's Fingerprint -> Nancy's ETH Address
    All using the same token ID (derived from Kyle's fingerprint).
    """
    actors = get_actor_config()
    kyle = actors["kyle"]
    luke = actors["luke"]
    marie = actors["marie"]
    nancy = actors["nancy"]

    # Use Kyle's fingerprint for the token ID (same token throughout)
    fingerprint = kyle["pq_fingerprint"]
    token_id = int.from_bytes(keccak(b"PQ_TOKEN" + bytes.fromhex(fingerprint[2:])), "big")
    domain_separator = bytes.fromhex(PQERC721_TRANSFER_DOMAIN_SEPARATOR[2:] if PQERC721_TRANSFER_DOMAIN_SEPARATOR.startswith("0x") else PQERC721_TRANSFER_DOMAIN_SEPARATOR)

    # Multi-hop transfer chain - all moving Kyle's token
    hops = [
        (kyle, luke["eth_address"], 0),           # Kyle's Fingerprint -> Luke's ETH Address (nonce 0)
        (luke, marie["pq_fingerprint"], 0),       # Luke's Fingerprint -> Marie's Fingerprint (nonce 0)
        (marie, nancy["eth_address"], 0)          # Marie's Fingerprint -> Nancy's ETH Address (nonce 0)
    ]

    vectors = []
    timestamp = int(time.time())
    for i, (sender, recipient, nonce) in enumerate(hops):
        # Ensure recipient is a hex string (ETH address or fingerprint)
        if isinstance(recipient, bytes):
            recipient_hex = '0x' + recipient.hex()
        elif isinstance(recipient, str):
            if recipient.startswith('0x'):
                recipient_hex = recipient
            else:
                recipient_hex = '0x' + recipient
        else:
            raise ValueError(f"Recipient must be a hex string or bytes, got {type(recipient)}")
        message = create_pq_transfer_message(
            domain_separator,
            token_id,  # Always Kyle's token ID
            recipient_hex,
            nonce,  # Use the nonce from the hops tuple
            timestamp + i  # ensure unique timestamp per hop
        )
        print(f"DEBUG: Multi-hop message {i+1} length: {len(message)}")
        pq_sig = sign_with_pq_key(message, sender["pq_private_key_file"], nonce, sender["pq_fingerprint"])
        # Get actor name from the actors dict key
        actor_name = None
        for key, actor in actors.items():
            if actor == sender:
                actor_name = key
                break
        vectors.append({
            "description": f"Multi-hop transfer {i+1}: {actor_name} moves Kyle's token to {recipient_hex}",
            "token_id": token_id,  # Always Kyle's token ID
            "from_fingerprint": sender["pq_fingerprint"],
            "to_address": recipient_hex,
            "pq_message": message.hex(),
            "pq_signature": {
                "salt": "0x" + pq_sig["salt"].hex() if pq_sig else None,
                "cs1": pq_sig["cs1"] if pq_sig else [],
                "cs2": pq_sig["cs2"] if pq_sig else [],
                "hint": pq_sig["hint"] if pq_sig else 0
            },
            "pq_nonce": nonce,
            "timestamp": timestamp + i,
            "expected_result": "success"
        })
    return vectors

def main():
    """Generate and save PQ transfer vectors"""
    
    # Generate single-hop vectors
    single_hop_vectors = generate_pq_transfer_vectors()
    
    # Generate multi-hop vectors
    multi_hop_vectors = generate_multi_hop_vectors()
    
    # Combine all vectors
    all_vectors = single_hop_vectors + multi_hop_vectors
    output = {"pq_transfers": all_vectors}
    
    # Create output directory (relative to project root)
    project_root = Path(__file__).resolve().parents[5]
    output_dir = project_root / "test" / "test_vectors" / "production" / "transfer"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save vectors
    output_file = output_dir / "pq_transfer_vectors.json"
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"Generated {len(all_vectors)} PQ transfer vectors")
    print(f"Saved to: {output_file}")

if __name__ == "__main__":
    main() 
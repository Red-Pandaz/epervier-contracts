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

from eip712_config import DOMAIN_SEPARATOR, PQERC721_TRANSFER_DOMAIN_SEPARATOR

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
    project_root = Path(__file__).resolve().parents[4]
    config_path = project_root / "test" / "test_keys" / "actors_config.json"
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
    project_root = Path(__file__).resolve().parents[4]
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
    alice = actors["alice"]
    bob = actors["bob"]
    charlie = actors["charlie"]
    danielle = actors["danielle"]
    
    # Create eth_account objects from private keys
    alice["eth_account"] = Account.from_key(alice["eth_private_key"])
    bob["eth_account"] = Account.from_key(bob["eth_private_key"])
    charlie["eth_account"] = Account.from_key(charlie["eth_private_key"])
    danielle["eth_account"] = Account.from_key(danielle["eth_private_key"])
    
    # Ensure all transfer vectors use pq_nonce = 0
    alice_pq_nonce = 0
    bob_pq_nonce = 0
    charlie_pq_nonce = 0
    danielle_pq_nonce = 0
    # For multi-hop, set nonce=0 for every hop
    hops = [
        (alice, bob["eth_address"], 0),
        (bob, charlie["pq_fingerprint"], 0),
        (charlie, danielle["eth_address"], 0)
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
    alice_token_id = calc_token_id(alice['pq_fingerprint'])
    bob_token_id = calc_token_id(bob['pq_fingerprint'])
    charlie_token_id = calc_token_id(charlie['pq_fingerprint'])
    danielle_token_id = calc_token_id(danielle['pq_fingerprint'])
    
    vectors = []
    current_timestamp = int(time.time())
    
    # Vector 1: Transfer from Alice's fingerprint to Bob's ETH address
    alice_pq_message = create_pq_transfer_message(
        domain_separator,
        alice_token_id,
        bob["eth_address"],
        alice_pq_nonce,
        current_timestamp
    )
    
    alice_pq_sig = sign_with_pq_key(
        alice_pq_message,
        alice["pq_private_key_file"],
        alice_pq_nonce,
        alice["pq_fingerprint"]
    )
    
    vectors.append({
        "description": "Transfer from Alice's fingerprint to Bob's ETH address",
        "token_id": alice_token_id,
        "from_fingerprint": alice["pq_fingerprint"],
        "to_address": bob["eth_address"],
        "pq_message": alice_pq_message.hex(),
        "pq_signature": {
            "salt": alice_pq_sig["salt"].hex() if alice_pq_sig else "0x" + "00" * 40,
            "cs1": [hex(x) for x in alice_pq_sig["cs1"]] if alice_pq_sig else [hex(0)] * 32,
            "cs2": [hex(x) for x in alice_pq_sig["cs2"]] if alice_pq_sig else [hex(0)] * 32,
            "hint": alice_pq_sig["hint"] if alice_pq_sig else 12345
        },
        "pq_nonce": alice_pq_nonce,
        "timestamp": current_timestamp,
        "expected_result": "success"
    })
    
    # Vector 2: Transfer from Bob's fingerprint to Charlie's ETH address
    bob_pq_message = create_pq_transfer_message(
        domain_separator,
        bob_token_id,
        charlie["eth_address"],
        bob_pq_nonce,
        current_timestamp + 1
    )
    
    bob_pq_sig = sign_with_pq_key(
        bob_pq_message,
        bob["pq_private_key_file"],
        bob_pq_nonce,
        bob["pq_fingerprint"]
    )
    
    vectors.append({
        "description": "Transfer from Bob's fingerprint to Charlie's ETH address",
        "token_id": bob_token_id,
        "from_fingerprint": bob["pq_fingerprint"],
        "to_address": charlie["eth_address"],
        "pq_message": bob_pq_message.hex(),
        "pq_signature": {
            "salt": bob_pq_sig["salt"].hex() if bob_pq_sig else "0x" + "00" * 40,
            "cs1": [hex(x) for x in bob_pq_sig["cs1"]] if bob_pq_sig else [hex(0)] * 32,
            "cs2": [hex(x) for x in bob_pq_sig["cs2"]] if bob_pq_sig else [hex(0)] * 32,
            "hint": bob_pq_sig["hint"] if bob_pq_sig else 12345
        },
        "pq_nonce": bob_pq_nonce,
        "timestamp": current_timestamp + 1,
        "expected_result": "success"
    })
    
    # Vector 3: Transfer from Charlie's fingerprint to Danielle's ETH address
    charlie_pq_message = create_pq_transfer_message(
        domain_separator,
        charlie_token_id,
        danielle["eth_address"],
        charlie_pq_nonce,
        current_timestamp + 2
    )
    
    charlie_pq_sig = sign_with_pq_key(
        charlie_pq_message,
        charlie["pq_private_key_file"],
        charlie_pq_nonce,
        charlie["pq_fingerprint"]
    )
    
    vectors.append({
        "description": "Transfer from Charlie's fingerprint to Danielle's ETH address",
        "token_id": charlie_token_id,
        "from_fingerprint": charlie["pq_fingerprint"],
        "to_address": danielle["eth_address"],
        "pq_message": charlie_pq_message.hex(),
        "pq_signature": {
            "salt": charlie_pq_sig["salt"].hex() if charlie_pq_sig else "0x" + "00" * 40,
            "cs1": [hex(x) for x in charlie_pq_sig["cs1"]] if charlie_pq_sig else [hex(0)] * 32,
            "cs2": [hex(x) for x in charlie_pq_sig["cs2"]] if charlie_pq_sig else [hex(0)] * 32,
            "hint": charlie_pq_sig["hint"] if charlie_pq_sig else 12345
        },
        "pq_nonce": charlie_pq_nonce,
        "timestamp": current_timestamp + 2,
        "expected_result": "success"
    })
    
    # Vector 4: Wrong signature test - Alice's token but Bob's signature
    wrong_pq_message = create_pq_transfer_message(
        domain_separator,
        alice_token_id,
        bob["eth_address"],
        alice_pq_nonce,
        current_timestamp + 3
    )
    
    wrong_pq_sig = sign_with_pq_key(
        wrong_pq_message,
        bob["pq_private_key_file"],  # Using Bob's key instead of Alice's
        bob_pq_nonce,
        bob["pq_fingerprint"]  # Bob's fingerprint instead of Alice's
    )
    
    vectors.append({
        "description": "Transfer with wrong signature (Alice's token, Bob's signature)",
        "token_id": alice_token_id,
        "from_fingerprint": alice["pq_fingerprint"],
        "to_address": bob["eth_address"],
        "pq_message": wrong_pq_message.hex(),
        "pq_signature": {
            "salt": wrong_pq_sig["salt"].hex() if wrong_pq_sig else "0x" + "00" * 40,
            "cs1": [hex(x) for x in wrong_pq_sig["cs1"]] if wrong_pq_sig else [hex(0)] * 32,
            "cs2": [hex(x) for x in wrong_pq_sig["cs2"]] if wrong_pq_sig else [hex(0)] * 32,
            "hint": wrong_pq_sig["hint"] if wrong_pq_sig else 12345
        },
        "pq_nonce": alice_pq_nonce,
        "timestamp": current_timestamp + 3,
        "expected_result": "failure"
    })
    
    # Vector 5: Transfer to zero address (should fail)
    alice_zero_message = create_pq_transfer_message(
        domain_separator,
        alice_token_id,
        "0x0000000000000000000000000000000000000000",
        alice_pq_nonce,
        current_timestamp + 4
    )
    
    alice_zero_sig = sign_with_pq_key(
        alice_zero_message,
        alice["pq_private_key_file"],
        alice_pq_nonce,
        alice["pq_fingerprint"]
    )
    
    vectors.append({
        "description": "Transfer to zero address (should fail)",
        "token_id": alice_token_id,
        "from_fingerprint": alice["pq_fingerprint"],
        "to_address": "0x0000000000000000000000000000000000000000",
        "pq_message": alice_zero_message.hex(),
        "pq_signature": {
            "salt": alice_zero_sig["salt"].hex() if alice_zero_sig else "0x" + "00" * 40,
            "cs1": [hex(x) for x in alice_zero_sig["cs1"]] if alice_zero_sig else [hex(0)] * 32,
            "cs2": [hex(x) for x in alice_zero_sig["cs2"]] if alice_zero_sig else [hex(0)] * 32,
            "hint": alice_zero_sig["hint"] if alice_zero_sig else 12345
        },
        "pq_nonce": alice_pq_nonce,
        "timestamp": current_timestamp + 4,
        "expected_result": "failure"
    })
    
    # Vector 6: Invalid domain separator (should fail)
    wrong_domain = hashlib.sha256("WRONG_DOMAIN".encode()).digest()
    alice_wrong_domain_message = create_pq_transfer_message(
        wrong_domain,
        alice_token_id,
        bob["eth_address"],
        alice_pq_nonce,
        current_timestamp + 5
    )
    
    alice_wrong_domain_sig = sign_with_pq_key(
        alice_wrong_domain_message,
        alice["pq_private_key_file"],
        alice_pq_nonce,
        alice["pq_fingerprint"]
    )
    
    vectors.append({
        "description": "Transfer with wrong domain separator (should fail)",
        "token_id": alice_token_id,
        "from_fingerprint": alice["pq_fingerprint"],
        "to_address": bob["eth_address"],
        "pq_message": alice_wrong_domain_message.hex(),
        "pq_signature": {
            "salt": alice_wrong_domain_sig["salt"].hex() if alice_wrong_domain_sig else "0x" + "00" * 40,
            "cs1": [hex(x) for x in alice_wrong_domain_sig["cs1"]] if alice_wrong_domain_sig else [hex(0)] * 32,
            "cs2": [hex(x) for x in alice_wrong_domain_sig["cs2"]] if alice_wrong_domain_sig else [hex(0)] * 32,
            "hint": alice_wrong_domain_sig["hint"] if alice_wrong_domain_sig else 12345
        },
        "pq_nonce": alice_pq_nonce,
        "timestamp": current_timestamp + 5,
        "expected_result": "failure"
    })
    
    return vectors

def generate_multi_hop_vectors() -> list:
    """
    Generate a sequence of PQ transfer vectors for multi-hop transfers of Alice's token:
    Alice's Fingerprint -> Bob's ETH Address -> Charlie's Fingerprint -> Danielle's ETH Address
    All using the same token ID (derived from Alice's fingerprint).
    """
    actors = get_actor_config()
    alice = actors["alice"]
    bob = actors["bob"]
    charlie = actors["charlie"]
    danielle = actors["danielle"]

    # Use Alice's fingerprint for the token ID (same token throughout)
    fingerprint = alice["pq_fingerprint"]
    token_id = int.from_bytes(keccak(b"PQ_TOKEN" + bytes.fromhex(fingerprint[2:])), "big")
    domain_separator = bytes.fromhex(PQERC721_TRANSFER_DOMAIN_SEPARATOR[2:] if PQERC721_TRANSFER_DOMAIN_SEPARATOR.startswith("0x") else PQERC721_TRANSFER_DOMAIN_SEPARATOR)

    # Multi-hop transfer chain - all moving Alice's token
    hops = [
        (alice, bob["eth_address"], 0),           # Alice's Fingerprint -> Bob's ETH Address (nonce 0)
        (bob, charlie["pq_fingerprint"], 0),      # Bob's Fingerprint -> Charlie's Fingerprint (nonce 0)
        (charlie, danielle["eth_address"], 0)     # Charlie's Fingerprint -> Danielle's ETH Address (nonce 0)
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
            token_id,  # Always Alice's token ID
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
            "description": f"Multi-hop transfer {i+1}: {actor_name} moves Alice's token to {recipient_hex}",
            "token_id": token_id,  # Always Alice's token ID
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
    project_root = Path(__file__).resolve().parents[4]
    output_dir = project_root / "test" / "test_vectors" / "transfer"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save vectors
    output_file = output_dir / "pq_transfer_vectors.json"
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"Generated {len(all_vectors)} PQ transfer vectors")
    print(f"Saved to: {output_file}")

if __name__ == "__main__":
    main() 
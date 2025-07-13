#!/usr/bin/env python3
"""
Production PQ Transfer Vector Generator
Generates vectors for PQERC721.sol (not Test version)
"""

import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak
import sys
import os

# Add the parent directory to the path to import eip712_config
sys.path.append(str(Path(__file__).resolve().parents[3]))  # test/python

print("Script loaded successfully!")

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[4]  # epervier-contracts
PRODUCTION_ACTORS_CONFIG_PATH = PROJECT_ROOT / "test" / "test_keys" / "production_actors_config.json"
OUTPUT_PATH = PROJECT_ROOT / "test/test_vectors/dev/pq_transfer_vectors.json"

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')

def encode_packed(*args):
    """Encode packed data (equivalent to abi.encodePacked)"""
    result = b''
    for arg in args:
        if isinstance(arg, bytes):
            result += arg
        elif isinstance(arg, str):
            result += arg.encode('utf-8')
        elif isinstance(arg, int):
            result += arg.to_bytes(32, 'big')
    return result

def load_production_actors_config():
    """Load the production actors config JSON"""
    with open(PRODUCTION_ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]

def get_pq_transfer_domain_separator_from_contract():
    """Get the PQ transfer domain separator from the deployed production contract"""
    # This will be updated after deployment
    # For now, return a placeholder - will be updated with actual value
    return "0x4f5b11e23105a6e787a84ea6ef25beb42ea36aca76481502da09c5391cd1fdc0"

def calculate_token_id(pq_fingerprint):
    """Calculate deterministic token ID for a PQ fingerprint"""
    # Same logic as contract: keccak256("PQ_TOKEN" + fingerprint)
    packed = b"PQ_TOKEN" + bytes.fromhex(pq_fingerprint[2:])  # Remove 0x prefix
    token_id_bytes = keccak(packed)
    return int.from_bytes(token_id_bytes, 'big')

def build_pq_transfer_message(domain_separator, token_id, recipient_address, pq_nonce, timestamp):
    """Build PQ transfer message"""
    # DOMAIN_SEPARATOR (32) + TOKEN_ID (32) + RECIPIENT (20) + PQ_NONCE (32) + TIMESTAMP (32) = 148 bytes
    domain_separator_bytes = bytes.fromhex(domain_separator[2:])  # Remove '0x' prefix
    recipient_bytes = bytes.fromhex(recipient_address[2:])  # Remove '0x' prefix
    
    return (
        domain_separator_bytes +
        token_id.to_bytes(32, 'big') +
        recipient_bytes +
        pq_nonce.to_bytes(32, 'big') +
        timestamp.to_bytes(32, 'big')
    )

def sign_with_pq_key(pq_transfer_message, pq_private_key_file):
    """Use sign_cli.py to sign the PQ transfer message"""
    from tempfile import NamedTemporaryFile
    import os
    
    # Write message to temp file
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(pq_transfer_message)
        tmp.flush()
        tmp_path = tmp.name
    
    # Find the project root
    project_root = Path(__file__).resolve().parents[4]  # epervier-contracts

    sign_cli = project_root / "ETHFALCON/python-ref/sign_cli.py"
    privkey_path = project_root / "test/test_keys" / pq_private_key_file
    venv_python = project_root / "ETHFALCON/python-ref/myenv/bin/python3"

    cmd = [
        str(venv_python), str(sign_cli), "sign",
        f"--privkey={privkey_path}",
        f"--data={pq_transfer_message.hex()}",
        "--version=epervier"
    ]
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    os.unlink(tmp_path)
    print("PQ sign_cli output:")
    print(result.stdout)
    
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

def main():
    print("Starting PRODUCTION PQ transfer vector generation...")
    print(f"Using production actors config: {PRODUCTION_ACTORS_CONFIG_PATH}")
    
    actors = load_production_actors_config()
    print(f"Loaded {len(actors)} production actors from config")
    
    # Create transfer scenarios
    transfers = [
        {
            "description": "Transfer from Kyle's fingerprint to Luke's ETH address",
            "from_actor": "kyle",
            "to_actor": "luke"
        },
        {
            "description": "Transfer from Luke's fingerprint to Marie's ETH address", 
            "from_actor": "luke",
            "to_actor": "marie"
        },
        {
            "description": "Transfer from Marie's fingerprint to Nancy's ETH address",
            "from_actor": "marie", 
            "to_actor": "nancy"
        },
        {
            "description": "Transfer from Nancy's fingerprint to Oscar's ETH address",
            "from_actor": "nancy",
            "to_actor": "oscar"
        },
        {
            "description": "Transfer from Oscar's fingerprint to Kyle's ETH address",
            "from_actor": "oscar",
            "to_actor": "kyle"
        }
    ]
    
    vectors = []
    domain_separator = get_pq_transfer_domain_separator_from_contract()
    
    for i, transfer in enumerate(transfers):
        print(f"Processing transfer {i+1}: {transfer['description']}")
        
        from_actor = actors[transfer["from_actor"]]
        to_actor = actors[transfer["to_actor"]]
        
        # Calculate token ID for the from_actor's fingerprint
        token_id = calculate_token_id(from_actor["pq_fingerprint"])
        print(f"Token ID: {token_id}")
        
        # Set up transfer parameters
        pq_nonce = 0  # Will be incremented after registration
        timestamp = 1752003834  # Fixed timestamp for consistency
        
        # Build PQ transfer message
        print("Building PQ transfer message...")
        pq_transfer_message = build_pq_transfer_message(
            domain_separator,
            token_id,
            to_actor["eth_address"],
            pq_nonce,
            timestamp
        )
        print(f"PQ transfer message length: {len(pq_transfer_message)} bytes")
        
        # Sign with PQ key
        print("Signing with PQ key...")
        pq_sig = sign_with_pq_key(pq_transfer_message, from_actor["pq_private_key_file"])
        if pq_sig is None:
            print(f"Failed to generate PQ signature for transfer {i+1}!")
            continue
        print(f"PQ signature generated: {len(pq_sig)} components")
        
        # Collect vector data
        print("Collecting vector data...")
        vector = {
            "description": transfer["description"],
            "token_id": token_id,
            "from_fingerprint": from_actor["pq_fingerprint"],
            "to_address": to_actor["eth_address"],
            "pq_message": pq_transfer_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            },
            "pq_nonce": pq_nonce,
            "timestamp": timestamp,
            "expected_result": "success"
        }
        vectors.append(vector)
    
    print(f"Writing {len(vectors)} production PQ transfer vectors to {OUTPUT_PATH}")
    with open(OUTPUT_PATH, "w") as f:
        json.dump({"pq_transfers": vectors}, f, indent=2)
    
    print("✅ Production PQ transfer vectors generated!")

if __name__ == "__main__":
    main() 
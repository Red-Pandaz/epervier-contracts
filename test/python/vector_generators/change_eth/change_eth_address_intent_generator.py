#!/usr/bin/env python3
"""
Generate test vectors for change ETH address intent in PQRegistry

This script generates test vectors for:
- Change ETH address intent (submitChangeETHAddressIntent)

The flow is:
1. Alice is registered (Alice ETH -> Alice PQ)
2. Alice's PQ key submits change intent containing Bob's ETH signature
3. Bob confirms the change

This is a key compromise recovery mechanism where Bob takes over Alice's PQ fingerprint.
"""

import json
import os
import sys
from pathlib import Path
from eth_account import Account
from eth_utils import keccak
import re

# Add the project root to the Python path
project_root = Path(__file__).resolve().parents[4]  # epervier-registry
sys.path.insert(0, str(project_root))

# Add the python directory to the path for EIP712 imports
sys.path.append(str(Path(__file__).resolve().parents[2]))
from eip712_helpers import *
from eip712_config import *

# Load actors configuration
ACTORS_CONFIG_PATH = project_root / "test" / "test_keys" / "actors_config.json"
print(f"DEBUG: project_root = {project_root}")
print(f"DEBUG: ACTORS_CONFIG_PATH = {ACTORS_CONFIG_PATH}")
print(f"DEBUG: File exists = {ACTORS_CONFIG_PATH.exists()}")

def get_actor_config():
    """Load the actors config JSON."""
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]



def create_base_eth_message(pq_fingerprint, new_eth_address, eth_nonce):
    """
    Create base ETH message for change ETH Address intent
    Format: "Intent to change ETH Address and bind with Epervier Fingerprint " + pqFingerprint + " to " + newEthAddress + ethNonce
    This is signed by Bob (new ETH Address) (no domain separator in content)
    """
    pattern = b"Intent to change ETH Address and bind with Epervier Fingerprint "
    message = (
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        b" to " +
        bytes.fromhex(new_eth_address[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def create_base_pq_message(old_eth_address, new_eth_address, base_eth_message, v, r, s, pq_nonce):
    """
    Create base PQ message for change ETH Address intent
    Format: DOMAIN_SEPARATOR + "Intent to change bound ETH Address from " + oldEthAddress + " to " + newEthAddress + baseETHMessage + v + r + s + pqNonce
    This matches the contract's parsePQChangeETHAddressIntentMessage function exactly
    """
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix, 32 bytes
    pattern = b"Intent to change bound ETH Address from "
    old_addr_bytes = bytes.fromhex(old_eth_address[2:])  # Remove "0x" prefix, 20 bytes
    to_pattern = b" to "
    new_addr_bytes = bytes.fromhex(new_eth_address[2:])  # Remove "0x" prefix, 20 bytes
    
    # Convert base_eth_message from hex string to bytes
    if isinstance(base_eth_message, bytes):
        base_eth_message_str = base_eth_message.hex()
    else:
        base_eth_message_str = base_eth_message

    base_eth_message_bytes = bytes.fromhex(base_eth_message_str[2:] if base_eth_message_str.startswith('0x') else base_eth_message_str)
    
    # Pad or truncate base_eth_message_bytes to exactly 140 bytes
    if len(base_eth_message_bytes) < 140:
        base_eth_message_bytes = base_eth_message_bytes + b'\x00' * (140 - len(base_eth_message_bytes))
    elif len(base_eth_message_bytes) > 140:
        base_eth_message_bytes = base_eth_message_bytes[:140]
    
    # Convert signature components to bytes
    v_bytes = v.to_bytes(1, 'big')  # 1 byte
    r_bytes = r.to_bytes(32, 'big')  # 32 bytes
    s_bytes = s.to_bytes(32, 'big')  # 32 bytes
    pq_nonce_bytes = pq_nonce.to_bytes(32, 'big')  # 32 bytes
    
    # Concatenate all components with DOMAIN_SEPARATOR at the start
    message = domain_separator_bytes + pattern + old_addr_bytes + to_pattern + new_addr_bytes + base_eth_message_bytes + v_bytes + r_bytes + s_bytes + pq_nonce_bytes
    
    return message

def sign_eth_message(new_eth_address: str, pq_fingerprint: str, eth_nonce: int, private_key: str) -> dict:
    """
    Sign the change ETH address intent message using the same pattern as registration intent
    """
    from eth_utils import keccak
    
    # Get the struct hash using the same pattern as registration intent
    struct_hash = get_change_eth_address_intent_struct_hash(new_eth_address, pq_fingerprint, eth_nonce)
    
    # Create EIP712 digest with domain separator (same pattern as registration intent)
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    digest = keccak(b'\x19\x01' + domain_separator_bytes + struct_hash)
    
    print(f"DEBUG: PYTHON struct_hash: {struct_hash.hex()}")
    print(f"DEBUG: PYTHON domain_separator: {domain_separator_bytes.hex()}")
    print(f"DEBUG: PYTHON digest: {digest.hex()}")
    
    # Sign the digest using the same pattern as registration intent
    signature = sign_eip712_message(digest, private_key)
    
    return signature

def sign_pq_message(message, pq_private_key_file):
    """Sign a message with PQ private key using sign_cli.py"""
    import subprocess
    
    try:
        # Sign with PQ key using sign_cli.py - use virtual environment like registration intent generator
        sign_cli = str(project_root / "ETHFALCON" / "python-ref" / "sign_cli.py")
        privkey_path = str(project_root / "test" / "test_keys" / pq_private_key_file)
        venv_python = str(project_root / "ETHFALCON" / "python-ref" / "myenv" / "bin" / "python3")
        
        cmd = [
            venv_python, sign_cli, "sign",
            f"--privkey={privkey_path}",
            f"--data={message.hex()}",
            "--version=epervier"
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=project_root / "ETHFALCON" / "python-ref")
        print(f"DEBUG: PQ sign_cli result.stdout: {result.stdout}")
        print(f"DEBUG: PQ sign_cli result.stderr: {result.stderr}")
        if result.returncode != 0:
            print(f"Error signing message: {result.stderr}")
            return None
        
        print(f"PQ sign_cli output:")
        print(result.stdout)
        
        # Parse the signature components from stdout
        lines = result.stdout.splitlines()
        print(f"DEBUG: All PQ signing output lines: {lines}")
        signature_data = {}
        try:
            print(f"DEBUG: PQ signing output lines:")
            i = 0
            while i < len(lines):
                line = lines[i]
                print(f"DEBUG: Line: '{line}'")
                
                if line.startswith("salt:"):
                    signature_data["salt"] = bytes.fromhex(line.split()[1])
                    i += 1
                elif line.startswith("hint:"):
                    signature_data["hint"] = int(line.split()[1])
                    i += 1
                elif line.startswith("cs1:"):
                    # Collect all cs1 values across multiple lines
                    cs1_content = line[4:].strip()  # Remove "cs1:" prefix
                    i += 1
                    # Continue reading lines until we hit another key or end
                    while i < len(lines) and not lines[i].startswith(("salt:", "hint:", "cs1:", "cs2:")):
                        cs1_content += " " + lines[i].strip()
                        i += 1
                    
                    # Parse the collected cs1 values
                    values = cs1_content.split()
                    parsed = []
                    for x in values:
                        print(f"DEBUG: cs1 value: '{x}' type: {type(x)}")
                        if x and re.match(r'^0x[0-9a-fA-F]+$', x):
                            try:
                                parsed.append(int(x[2:], 16))
                            except Exception as e:
                                print(f"Error parsing cs1 value '{x}': {e}")
                        elif x:
                            print(f"Skipping non-hex cs1 value: '{x}'")
                    signature_data["cs1"] = parsed
                    
                elif line.startswith("cs2:"):
                    # Collect all cs2 values across multiple lines
                    cs2_content = line[4:].strip()  # Remove "cs2:" prefix
                    i += 1
                    # Continue reading lines until we hit another key or end
                    while i < len(lines) and not lines[i].startswith(("salt:", "hint:", "cs1:", "cs2:")):
                        cs2_content += " " + lines[i].strip()
                        i += 1
                    
                    # Parse the collected cs2 values
                    values = cs2_content.split()
                    parsed = []
                    for x in values:
                        print(f"DEBUG: cs2 value: '{x}' type: {type(x)}")
                        if x and re.match(r'^0x[0-9a-fA-F]+$', x):
                            try:
                                parsed.append(int(x[2:], 16))
                            except Exception as e:
                                print(f"Error parsing cs2 value '{x}': {e}")
                        elif x:
                            print(f"Skipping non-hex cs2 value: '{x}'")
                    signature_data["cs2"] = parsed
                else:
                    i += 1
        except Exception as e:
            print(f"Exception during PQ signature parsing: {e}")
            print(f"Offending line: '{line}'")
            return None
        
        if not all(key in signature_data for key in ["salt", "hint", "cs1", "cs2"]):
            print(f"Failed to parse signature components")
            return None
        
        return {
            "salt": signature_data["salt"].hex(),
            "hint": signature_data["hint"],
            "cs1": [hex(x) for x in signature_data["cs1"]],
            "cs2": [hex(x) for x in signature_data["cs2"]]
        }
        
    except Exception as e:
        print(f"Error in PQ signing: {e}")
        return None

def generate_change_eth_address_intent_vectors():
    """Generate test vectors for change ETH address intent"""
    
    change_intent_vectors = []
    actors = get_actor_config()
    
    # Define the cycling pattern: alice -> bob -> charlie -> danielle -> eve -> frank -> grace -> henry -> iris -> jack -> alice
    actor_cycle = ["alice", "bob", "charlie", "danielle", "eve", "frank", "grace", "henry", "iris", "jack"]
    
    for i in range(10):
        current_actor_name = actor_cycle[i]
        next_actor_name = actor_cycle[(i + 1) % 10]  # Wrap around to alice for the last one
        
        current_actor = actors[current_actor_name]
        next_actor = actors[next_actor_name]
        
        print(f"Generating change ETH address intent vector for {current_actor_name} -> {next_actor_name}...")
        
        # Current actor is giving their PQ fingerprint to next actor
        old_eth_address = current_actor["eth_address"]  # Current actor's ETH address
        new_eth_address = next_actor["eth_address"]     # Next actor's ETH address
        pq_fingerprint = current_actor["pq_fingerprint"] # Current actor's PQ fingerprint
        
        # Nonces - each actor starts with nonce 0 for ETH, and PQ nonce increases with each change
        eth_nonce = 0  # Next actor's ETH nonce (always 0 for new actor)
        pq_nonce = 2  # Current actor's PQ nonce (2 for change ETH address intent after registration)
        
        # Step 1: Next actor signs the base ETH message
        struct_hash = get_change_eth_address_intent_struct_hash(new_eth_address, pq_fingerprint, eth_nonce)
        domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
        digest = keccak(b'\x19\x01' + domain_separator_bytes + struct_hash)
        print(f"DEBUG: PYTHON struct_hash: {struct_hash.hex()}")
        print(f"DEBUG: PYTHON domain_separator: {domain_separator_bytes.hex()}")
        print(f"DEBUG: PYTHON digest: {digest.hex()}")
        # Recover address from signature (after signing, below)
        base_eth_message = create_base_eth_message(pq_fingerprint, new_eth_address, eth_nonce)
        eth_signature = sign_eth_message(new_eth_address, pq_fingerprint, eth_nonce, next_actor["eth_private_key"])  # Next actor signs
        
        # Step 2: Current actor's PQ key signs the complete message containing next actor's signature
        base_pq_message = create_base_pq_message(
            old_eth_address, new_eth_address, base_eth_message,
            eth_signature["v"], eth_signature["r"], eth_signature["s"], pq_nonce)
        pq_signature = sign_pq_message(base_pq_message, current_actor["pq_private_key_file"])  # Current actor's PQ key signs
        
        if pq_signature is None:
            print(f"Failed to generate PQ signature for {current_actor_name}")
            continue
        
        # Create the full ETH message for contract submission
        # The basePQMessage should be the message that was signed by the PQ key
        # Use the already correctly constructed base_pq_message
        base_pq_message_for_contract = base_pq_message  # Use the correctly constructed message
        
        eth_message = (
            bytes.fromhex(DOMAIN_SEPARATOR[2:]) +
            b"Intent to change ETH Address and bind with Epervier Fingerprint " +
            bytes.fromhex(pq_fingerprint[2:]) +
            base_pq_message_for_contract +
            bytes.fromhex(pq_signature["salt"]) +
            b"".join(int(x, 16).to_bytes(32, "big") for x in pq_signature["cs1"]) +
            b"".join(int(x, 16).to_bytes(32, "big") for x in pq_signature["cs2"]) +
            int(pq_signature["hint"]).to_bytes(32, "big") +
            eth_nonce.to_bytes(32, "big")
        )
        
        change_intent_vector = {
            "current_actor": current_actor_name,
            "new_actor": next_actor_name,
            "old_eth_address": old_eth_address,
            "new_eth_address": new_eth_address,
            "pq_fingerprint": pq_fingerprint,
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_message": eth_message.hex(),
            "eth_signature": {
                "v": eth_signature["v"],
                "r": eth_signature["r"],
                "s": eth_signature["s"]
            },
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
        change_intent_vectors.append(change_intent_vector)
    
    return change_intent_vectors

def main():
    """Main function to generate and save test vectors"""
    print("Generating change ETH address intent test vectors...")
    
    try:
        vectors = generate_change_eth_address_intent_vectors()
        
        # Save to JSON file
        output_file = project_root / "test/test_vectors/change_eth/change_eth_address_intent_vectors.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump({"change_eth_address_intent": vectors}, f, indent=2)
        print(f"Wrote {len(vectors)} change ETH address intent vectors to {output_file}")
        
        # Print sample vector for verification
        if vectors:
            print("\nSample change ETH address intent vector:")
            sample = vectors[0]
            print(f"Current Actor: {sample['current_actor']}")
            print(f"New Actor: {sample['new_actor']}")
            print(f"Old ETH Address: {sample['old_eth_address']}")
            print(f"New ETH Address: {sample['new_eth_address']}")
            print(f"PQ Fingerprint: {sample['pq_fingerprint']}")
            print(f"ETH Nonce: {sample['eth_nonce']}")
            print(f"PQ Nonce: {sample['pq_nonce']}")
        
    except Exception as e:
        print(f"Error generating vectors: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
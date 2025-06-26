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

# Add the project root to the Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Load actors configuration
ACTORS_CONFIG_PATH = project_root / "test" / "test_keys" / "actors_config.json"

def get_actor_config():
    """Load the actors config JSON."""
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]

# Domain separator from the contract
DOMAIN_SEPARATOR = keccak(b"PQRegistry")

def create_base_eth_message(domain_separator, pq_fingerprint, new_eth_address, eth_nonce):
    """
    Create base ETH message for change ETH address intent
    Format: DOMAIN_SEPARATOR + "Intent to change ETH Address and bond with Epervier fingerprint " + pqFingerprint + " to " + newEthAddress + ethNonce
    This is signed by Bob (new ETH address)
    """
    pattern = b"Intent to change ETH Address and bond with Epervier fingerprint "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        b" to " +
        bytes.fromhex(new_eth_address[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, "big")
    )
    return message

def create_base_pq_message(domain_separator, old_eth_address, new_eth_address, base_eth_message, eth_signature, pq_nonce):
    """
    Create base PQ message for change ETH address intent
    Format: DOMAIN_SEPARATOR + "Intent to change bound ETH Address from " + oldEthAddress + " to " + newEthAddress + baseETHMessage + v + r + s + pqNonce
    This is signed by Alice's PQ key
    """
    pattern = b"Intent to change bound ETH Address from "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(old_eth_address[2:]) +  # Remove "0x" prefix
        b" to " +
        bytes.fromhex(new_eth_address[2:]) +  # Remove "0x" prefix
        base_eth_message +
        eth_signature["v"].to_bytes(1, "big") +
        eth_signature["r"].to_bytes(32, "big") +
        eth_signature["s"].to_bytes(32, "big") +
        pq_nonce.to_bytes(32, "big")
    )
    return message

def sign_eth_message(message_bytes, private_key):
    """Sign a message with ETH private key (Ethereum Signed Message)"""
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message_bytes)).encode()
    eth_signed_message = prefix + message_bytes
    eth_signed_message_hash = keccak(eth_signed_message)
    account = Account.from_key(private_key)
    sig = Account._sign_hash(eth_signed_message_hash, private_key=account.key)
    return {
        "v": sig.v,
        "r": hex(sig.r),
        "s": hex(sig.s)
    }

def sign_pq_message(message, pq_private_key_file):
    """Sign a message with PQ private key using sign_cli.py"""
    import subprocess
    
    try:
        # Sign with PQ key using sign_cli.py
        sign_cli = str(project_root / "ETHFALCON" / "python-ref" / "sign_cli.py")
        privkey_path = str(project_root / "test" / "test_keys" / pq_private_key_file)
        
        cmd = [
            "python3", sign_cli, "sign",
            f"--privkey={privkey_path}",
            f"--data={message.hex()}",
            "--version=epervier"
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=project_root / "ETHFALCON" / "python-ref")
        
        if result.returncode != 0:
            print(f"Error signing message: {result.stderr}")
            return None
        
        print(f"PQ sign_cli output:")
        print(result.stdout)
        
        # Parse the signature components from stdout
        lines = result.stdout.splitlines()
        signature_data = {}
        for line in lines:
            if line.startswith("salt:"):
                signature_data["salt"] = bytes.fromhex(line.split()[1])
            elif line.startswith("hint:"):
                signature_data["hint"] = int(line.split()[1])
            elif line.startswith("cs1:"):
                signature_data["cs1"] = [int(x, 16) for x in line.split()[1:]]
            elif line.startswith("cs2:"):
                signature_data["cs2"] = [int(x, 16) for x in line.split()[1:]]
        
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
        base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, pq_fingerprint, new_eth_address, eth_nonce)
        eth_signature = sign_eth_message(base_eth_message, next_actor["eth_private_key"])  # Next actor signs
        
        # Step 2: Current actor's PQ key signs the complete message containing next actor's signature
        base_pq_message = create_base_pq_message(
            DOMAIN_SEPARATOR, old_eth_address, new_eth_address, base_eth_message,
            {"v": eth_signature["v"], "r": int(eth_signature["r"], 16), "s": int(eth_signature["s"], 16)}, pq_nonce)
        pq_signature = sign_pq_message(base_pq_message, current_actor["pq_private_key_file"])  # Current actor's PQ key signs
        
        if pq_signature is None:
            print(f"Failed to generate PQ signature for {current_actor_name}")
            continue
        
        # Create the full ETH message for contract submission
        # The basePQMessage should be the message that was signed by the PQ key
        base_pq_message_for_contract = (
            DOMAIN_SEPARATOR +
            b"Intent to change bound ETH Address from " +
            bytes.fromhex(old_eth_address[2:]) +  # Remove "0x" prefix
            b" to " +
            bytes.fromhex(new_eth_address[2:]) +  # Remove "0x" prefix
            base_eth_message +
            eth_signature["v"].to_bytes(1, "big") +
            int(eth_signature["r"], 16).to_bytes(32, "big") +
            int(eth_signature["s"], 16).to_bytes(32, "big") +
            pq_nonce.to_bytes(32, "big")
        )
        
        eth_message = (
            DOMAIN_SEPARATOR +
            b"Intent to change ETH Address and bond with Epervier fingerprint " +
            bytes.fromhex(pq_fingerprint[2:]) +
            base_pq_message_for_contract +
            bytes.fromhex(pq_signature["salt"]) +
            b"".join(int(x, 16).to_bytes(32, "big") for x in pq_signature["cs1"]) +
            b"".join(int(x, 16).to_bytes(32, "big") for x in pq_signature["cs2"]) +
            pq_signature["hint"].to_bytes(32, "big") +
            eth_nonce.to_bytes(32, "big")
        )
        
        change_intent_vector = {
            "current_actor": current_actor_name,
            "new_actor": next_actor_name,
            "old_eth_address": old_eth_address,
            "new_eth_address": new_eth_address,
            "pq_fingerprint": pq_fingerprint,
            "base_eth_message": base_eth_message.hex(),
            "base_pq_message": base_pq_message.hex(),
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
        output_file = project_root / "test" / "test_vectors" / "change_eth_address_intent_vectors.json"
        with open(output_file, 'w') as f:
            json.dump({"change_eth_address_intent": vectors}, f, indent=2)
        
        print(f"Generated {len(vectors)} change ETH address intent vectors")
        print(f"Vectors saved to {output_file}")
        
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
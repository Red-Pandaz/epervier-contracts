#!/usr/bin/env python3
"""
Generator for cancel change ETH address intent test vectors.
"""

import json
import sys
from pathlib import Path
from eth_account import Account
from eth_hash.auto import keccak

# Add the project root to the path
project_root = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(project_root / "ETHFALCON" / "python-ref"))
sys.path.append(str(project_root / "test" / "python"))

# Import the correct domain separator
from production_eip712_config import DOMAIN_SEPARATOR

# Convert the domain separator from hex string to bytes
DOMAIN_SEPARATOR_BYTES = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix

def get_actor_config():
    """Load actor configuration from JSON file"""
    config_file = project_root / "test" / "test_keys" / "production_actors_config.json"
    with open(config_file, 'r') as f:
        config = json.load(f)
        return config["actors"]

def create_cancel_change_eth_address_message(domain_separator, current_eth_address, pq_nonce):
    """
    Create PQ message for canceling change ETH address intent
    Format: DOMAIN_SEPARATOR + "Remove change intent from ETH Address " + ethAddress + pqNonce
    This is signed by the PQ key
    """
    pattern = b"Remove change intent from ETH Address "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(current_eth_address[2:]) +  # Remove "0x" prefix
        pq_nonce.to_bytes(32, "big")
    )
    return message

def sign_pq_message(message, pq_private_key_file):
    """Sign a message with PQ private key using sign_cli.py"""
    import subprocess
    
    try:
        # Sign with PQ key using sign_cli.py - use virtual environment like other generators
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
        result = subprocess.run(cmd, capture_output=True, text=True)
        
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

def generate_cancel_change_eth_address_intent_vectors():
    """Generate test vectors for canceling change ETH address intents for all 5 production actors"""
    cancel_vectors = []
    actors = get_actor_config()
    actor_names = ["kyle", "luke", "marie", "nancy", "oscar"]
    num_actors = len(actor_names)

    for i in range(num_actors):
        current_actor_name = actor_names[i]
        next_actor_name = actor_names[(i + 1) % num_actors]  # Wrap around to kyle for the last one
        current_actor = actors[current_actor_name]
        next_actor = actors[next_actor_name]

        print(f"Generating cancel change ETH address intent vector for {current_actor_name} -> {next_actor_name}...")

        pending_change_address = next_actor["eth_address"]
        pq_fingerprint = current_actor["pq_fingerprint"]

        pq_nonce = 3  # PQ nonce for cancel operation
        eth_nonce = 1  # ETH nonce for cancel operation

        pq_message = create_cancel_change_eth_address_message(DOMAIN_SEPARATOR_BYTES, pending_change_address, pq_nonce)
        pq_signature = sign_pq_message(pq_message, current_actor["pq_private_key_file"])
        if pq_signature is None:
            print(f"Failed to generate PQ signature for {current_actor_name}")
            continue

        cancel_vector = {
            "current_actor": current_actor_name,
            "current_eth_address": current_actor["eth_address"],
            "pending_change_address": pending_change_address,
            "pq_fingerprint": pq_fingerprint,
            "pq_message": pq_message.hex(),
            "pq_signature": pq_signature,
            "pq_nonce": pq_nonce,
            "eth_nonce": eth_nonce
        }
        cancel_vectors.append(cancel_vector)

    return cancel_vectors

def main():
    """Main function to generate and save test vectors"""
    print("Generating cancel change ETH address intent test vectors...")
    
    try:
        vectors = generate_cancel_change_eth_address_intent_vectors()
        
        # Save to JSON file
        output_file = project_root / "test/test_vectors/production/change_eth/change_eth_address_cancel_pq_vectors.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump({"change_eth_address_cancel_pq": vectors}, f, indent=2)
        
        print(f"Generated {len(vectors)} cancel change ETH address intent vectors")
        print(f"Vectors saved to {output_file}")
        
        # Print sample vector for verification
        if vectors:
            print("\nSample cancel change ETH address intent vector:")
            vector = vectors[0]
            print(f"Current Actor: {vector['current_actor']}")
            print(f"Current ETH Address: {vector['current_eth_address']}")
            print(f"Pending Change Address: {vector['pending_change_address']}")
            print(f"PQ Fingerprint: {vector['pq_fingerprint']}")
            print(f"PQ Nonce: {vector['pq_nonce']}")
            print(f"ETH Nonce: {vector['eth_nonce']}")
        
    except Exception as e:
        print(f"Error generating vectors: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
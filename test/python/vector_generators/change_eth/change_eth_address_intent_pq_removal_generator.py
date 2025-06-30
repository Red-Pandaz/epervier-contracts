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
project_root = Path(__file__).resolve().parents[3]
sys.path.append(str(project_root))

# Domain separator (same as in the contract)
DOMAIN_SEPARATOR = bytes.fromhex("5f5d847b41fe04c02ecf9746150300028bfc195e7981ae8fe39fe8b7a745650f")

def get_actor_config():
    """Load actor configuration from JSON file"""
    config_file = project_root / "test" / "test_keys" / "actors_config.json"
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
    """Generate test vectors for canceling change ETH address intents for all 10 actors"""
    cancel_vectors = []
    actors = get_actor_config()
    actor_names = list(actors.keys())
    num_actors = len(actor_names)

    for i in range(num_actors):
        current_actor_name = actor_names[i]
        current_actor = actors[current_actor_name]

        print(f"Generating cancel change ETH address intent vector for {current_actor_name}...")

        current_eth_address = current_actor["eth_address"]
        pq_fingerprint = current_actor["pq_fingerprint"]

        # Nonces for cancel operation
        pq_nonce = 3  # PQ nonce for cancel operation
        eth_nonce = 1  # ETH nonce for cancel operation

        # Create the PQ cancel message and sign it with PQ key
        pq_message = create_cancel_change_eth_address_message(DOMAIN_SEPARATOR, current_eth_address, pq_nonce)
        pq_signature = sign_pq_message(pq_message, current_actor["pq_private_key_file"])
        
        if pq_signature is None:
            print(f"Failed to generate PQ signature for {current_actor_name}")
            continue

        cancel_vector = {
            "current_actor": current_actor_name,
            "current_eth_address": current_eth_address,
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
        output_file = project_root / "test" / "test_vectors" / "change_eth_address_cancel_pq_vectors.json"
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
            print(f"PQ Fingerprint: {vector['pq_fingerprint']}")
            print(f"PQ Nonce: {vector['pq_nonce']}")
            print(f"ETH Nonce: {vector['eth_nonce']}")
        
    except Exception as e:
        print(f"Error generating vectors: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
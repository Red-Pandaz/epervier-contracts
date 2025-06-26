#!/usr/bin/env python3
"""
Generator for change ETH address confirmation test vectors.
"""

import json
import sys
from pathlib import Path
from eth_account import Account
from eth_hash.auto import keccak

# Add the project root to the path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))

# Domain separator (same as in the contract)
DOMAIN_SEPARATOR = bytes.fromhex("5f5d847b41fe04c02ecf9746150300028bfc195e7981ae8fe39fe8b7a745650f")

def get_actor_config():
    """Load actor configuration from JSON file"""
    config_file = project_root / "test" / "test_keys" / "actors_config.json"
    with open(config_file, 'r') as f:
        config = json.load(f)
        return config["actors"]

def create_base_pq_confirm_message(domain_separator, old_eth_address, new_eth_address, pq_nonce):
    """
    Create base PQ message for change ETH address confirmation
    Format: DOMAIN_SEPARATOR + "Confirm changing ETH address from " + oldEthAddress + " to " + newEthAddress + pqNonce
    This is signed by the PQ key
    """
    pattern = b"Confirm changing ETH address from "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(old_eth_address[2:]) +  # Remove "0x" prefix
        b" to " +
        bytes.fromhex(new_eth_address[2:]) +  # Remove "0x" prefix
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

def generate_change_eth_address_confirmation_vectors():
    """Generate test vectors for change ETH address confirmation for all 10 actors"""
    confirmation_vectors = []
    actors = get_actor_config()
    actor_names = list(actors.keys())
    num_actors = len(actor_names)

    for i in range(num_actors):
        current_actor_name = actor_names[i]
        next_actor_name = actor_names[(i + 1) % num_actors]
        current_actor = actors[current_actor_name]
        next_actor = actors[next_actor_name]

        print(f"Generating change ETH address confirmation vector for {current_actor_name} -> {next_actor_name}...")

        old_eth_address = current_actor["eth_address"]
        new_eth_address = next_actor["eth_address"]
        pq_fingerprint = current_actor["pq_fingerprint"]

        eth_nonce = 1  # Next actor's ETH nonce (1 for confirmation)
        pq_nonce = 3   # Current actor's PQ nonce (3 for confirmation)

        base_pq_message = create_base_pq_confirm_message(DOMAIN_SEPARATOR, old_eth_address, new_eth_address, pq_nonce)
        pq_signature = sign_pq_message(base_pq_message, current_actor["pq_private_key_file"])
        if pq_signature is None:
            print(f"Failed to generate PQ signature for {current_actor_name}")
            continue

        eth_message = (
            DOMAIN_SEPARATOR +
            b"Confirm change ETH Address for Epervier fingerprint " +
            bytes.fromhex(pq_fingerprint[2:]) +
            base_pq_message +
            bytes.fromhex(pq_signature["salt"]) +
            b"".join(int(x, 16).to_bytes(32, "big") for x in pq_signature["cs1"]) +
            b"".join(int(x, 16).to_bytes(32, "big") for x in pq_signature["cs2"]) +
            pq_signature["hint"].to_bytes(32, "big") +
            eth_nonce.to_bytes(32, "big")
        )
        eth_signature = sign_eth_message(eth_message, next_actor["eth_private_key"])

        confirmation_vector = {
            "current_actor": current_actor_name,
            "new_actor": next_actor_name,
            "old_eth_address": old_eth_address,
            "new_eth_address": new_eth_address,
            "pq_fingerprint": pq_fingerprint,
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
        confirmation_vectors.append(confirmation_vector)

    return confirmation_vectors

def main():
    """Main function to generate and save test vectors"""
    print("Generating change ETH address confirmation test vectors...")
    
    try:
        vectors = generate_change_eth_address_confirmation_vectors()
        
        # Save to JSON file
        output_file = project_root / "test" / "test_vectors" / "change_eth_address_confirmation_vectors.json"
        with open(output_file, 'w') as f:
            json.dump({"change_eth_address_confirmation": vectors}, f, indent=2)
        
        print(f"Generated {len(vectors)} change ETH address confirmation vectors")
        print(f"Vectors saved to {output_file}")
        
        # Print sample vector for verification
        if vectors:
            print("\nSample change ETH address confirmation vector:")
            vector = vectors[0]
            print(f"Current Actor: {vector['current_actor']}")
            print(f"New Actor: {vector['new_actor']}")
            print(f"Old ETH Address: {vector['old_eth_address']}")
            print(f"New ETH Address: {vector['new_eth_address']}")
            print(f"PQ Fingerprint: {vector['pq_fingerprint']}")
            print(f"ETH Nonce: {vector['eth_nonce']}")
            print(f"PQ Nonce: {vector['pq_nonce']}")
        
    except Exception as e:
        print(f"Error generating vectors: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
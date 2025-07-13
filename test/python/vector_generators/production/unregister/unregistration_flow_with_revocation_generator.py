#!/usr/bin/env python3
"""
Generator for unregistration flow with revocation test vectors.
Scenario: PQ initiates unregistration intent → PQ revokes → PQ retries → ETH confirms
"""

import json
import sys
from pathlib import Path
from eth_account import Account
from eth_hash.auto import keccak
import os
import traceback

# Add the project root to the path
project_root = Path(__file__).resolve().parents[5]  # epervier-contracts
sys.path.append(str(project_root))
sys.path.append(str(project_root / "test" / "python"))

# Import the correct domain separator
from production_eip712_config import DOMAIN_SEPARATOR

# Convert the domain separator from hex string to bytes
DOMAIN_SEPARATOR_BYTES = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix

def get_actor_config():
    config_file = project_root / "test" / "test_keys" / "production_actors_config.json"
    with open(config_file, 'r') as f:
        config = json.load(f)
        return config["actors"]

def create_base_pq_unregistration_intent_message(domain_separator, eth_address, pq_nonce):
    pattern = b"Intent to unregister from Epervier Fingerprint from address "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(eth_address[2:]) +
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_pq_unregistration_intent_message(domain_separator, eth_address, base_eth_message, v, r, s, pq_nonce):
    pattern = b"Intent to unregister from Epervier Fingerprint from address "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(eth_address[2:]) +
        base_eth_message +
        v.to_bytes(1, 'big') +
        r.to_bytes(32, 'big') +
        s.to_bytes(32, 'big') +
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_pq_remove_unregistration_intent_message(domain_separator, eth_address, pq_nonce):
    pattern = b"Remove unregistration intent from ETH Address "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(eth_address[2:]) +
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_base_eth_unregistration_confirmation_message(domain_separator, pq_fingerprint, eth_nonce):
    pattern = b"Confirm unregistration from Epervier Fingerprint "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def create_pq_unregistration_confirmation_message(domain_separator, eth_address, base_eth_message, v, r, s, pq_nonce):
    pattern = b"Confirm unregistration from ETH Address "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(eth_address[2:]) +
        base_eth_message +
        v.to_bytes(1, 'big') +
        r.to_bytes(32, 'big') +
        s.to_bytes(32, 'big') +
        pq_nonce.to_bytes(32, 'big')
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
        "r": sig.r,  # Return as integer, not hex string
        "s": sig.s   # Return as integer, not hex string
    }

def sign_pq_message(message, pq_private_key_file):
    import subprocess
    try:
        sign_cli = str(project_root / "ETHFALCON" / "python-ref" / "sign_cli.py")
        privkey_path = str(project_root / "test" / "test_keys" / pq_private_key_file)
        venv_python = str(project_root / "ETHFALCON" / "python-ref" / "myenv" / "bin" / "python3")
        cmd = [
            venv_python, sign_cli, "sign",
            f"--privkey={privkey_path}",
            f"--data={message.hex()}",
            "--version=epervier"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error signing message: {result.stderr}")
            return None
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

def generate_unregistration_flow_with_revocation_vectors():
    vectors = []
    actors = get_actor_config()
    actor_names = list(actors.keys())
    for actor_name in actor_names:
        actor = actors[actor_name]
        print(f"Generating unregistration flow with revocation vectors for {actor_name}...")
        eth_address = actor["eth_address"]
        pq_fingerprint = actor["pq_fingerprint"]
        pq_private_key_file = actor["pq_private_key_file"]
        eth_private_key = actor["eth_private_key"]
        # Step 1: PQ initiates unregistration intent (PQ nonce 0, ETH nonce 0)
        pq_nonce_0 = 0
        eth_nonce_0 = 0
        base_pq_message_0 = create_base_pq_unregistration_intent_message(DOMAIN_SEPARATOR_BYTES, eth_address, pq_nonce_0)
        pq_message_0 = create_pq_unregistration_intent_message(
            DOMAIN_SEPARATOR_BYTES, eth_address, base_pq_message_0, 0, 0, 0, pq_nonce_0
        )
        pq_signature_0 = sign_pq_message(pq_message_0, pq_private_key_file)
        if pq_signature_0 is None:
            print(f"Failed to generate PQ signature for {actor_name} step 1")
            continue
        # Step 2: PQ revokes unregistration intent (PQ nonce 3, after registration and unregistration intent)
        pq_nonce_1 = 3
        pq_remove_message = create_pq_remove_unregistration_intent_message(DOMAIN_SEPARATOR_BYTES, eth_address, pq_nonce_1)
        pq_remove_signature = sign_pq_message(pq_remove_message, pq_private_key_file)
        if pq_remove_signature is None:
            print(f"Failed to generate PQ remove signature for {actor_name}")
            continue
        # Step 3: PQ retries unregistration intent (PQ nonce 2, ETH nonce 1)
        pq_nonce_2 = 2
        eth_nonce_1 = 1
        base_pq_message_1 = create_base_pq_unregistration_intent_message(DOMAIN_SEPARATOR_BYTES, eth_address, pq_nonce_2)
        pq_message_1 = create_pq_unregistration_intent_message(
            DOMAIN_SEPARATOR_BYTES, eth_address, base_pq_message_1, 0, 0, 0, pq_nonce_2
        )
        pq_signature_1 = sign_pq_message(pq_message_1, pq_private_key_file)
        if pq_signature_1 is None:
            print(f"Failed to generate PQ signature for {actor_name} step 3")
            continue
        # Step 4: ETH confirms unregistration (ETH nonce 2, PQ nonce 3)
        eth_nonce_2 = 2
        pq_nonce_3 = 3
        base_eth_confirm_message = create_base_eth_unregistration_confirmation_message(DOMAIN_SEPARATOR_BYTES, pq_fingerprint, eth_nonce_2)
        eth_confirm_signature = sign_eth_message(base_eth_confirm_message, eth_private_key)
        pq_confirm_message = create_pq_unregistration_confirmation_message(
            DOMAIN_SEPARATOR_BYTES, eth_address, base_eth_confirm_message,
            eth_confirm_signature["v"], eth_confirm_signature["r"], eth_confirm_signature["s"], pq_nonce_3
        )
        pq_confirm_signature = sign_pq_message(pq_confirm_message, pq_private_key_file)
        if pq_confirm_signature is None:
            print(f"Failed to generate PQ confirm signature for {actor_name}")
            continue
        scenario_vector = {
            "actor": actor_name,
            "eth_address": eth_address,
            "pq_fingerprint": pq_fingerprint,
            "steps": [
                {
                    "step": 1,
                    "description": "PQ initiates unregistration intent",
                    "base_pq_message": base_pq_message_0.hex(),
                    "pq_message": pq_message_0.hex(),
                    "pq_signature": pq_signature_0,
                    "pq_nonce": pq_nonce_0,
                    "eth_nonce": eth_nonce_0
                },
                {
                    "step": 2,
                    "description": "PQ revokes unregistration intent",
                    "pq_message": pq_remove_message.hex(),
                    "pq_signature": pq_remove_signature,
                    "pq_nonce": pq_nonce_1
                },
                {
                    "step": 3,
                    "description": "PQ retries unregistration intent",
                    "base_pq_message": base_pq_message_1.hex(),
                    "pq_message": pq_message_1.hex(),
                    "pq_signature": pq_signature_1,
                    "pq_nonce": pq_nonce_2,
                    "eth_nonce": eth_nonce_1
                },
                {
                    "step": 4,
                    "description": "ETH confirms unregistration",
                    "base_eth_message": base_eth_confirm_message.hex(),
                    "eth_signature": eth_confirm_signature,
                    "pq_message": pq_confirm_message.hex(),
                    "pq_signature": pq_confirm_signature,
                    "pq_nonce": pq_nonce_3,
                    "eth_nonce": eth_nonce_2
                }
            ]
        }
        vectors.append(scenario_vector)
    return vectors

def main():
    print("Generating unregistration flow with revocation test vectors...")
    try:
        vectors = generate_unregistration_flow_with_revocation_vectors()
        # Build remove_intent array for PQ removal step (step 2 for each actor)
        remove_intent = []
        for scenario in vectors:
            # Step 2: PQ revokes unregistration intent
            pq_removal_step = scenario["steps"][1]
            remove_intent.append({
                "eth_address": scenario["eth_address"],
                "pq_fingerprint": scenario["pq_fingerprint"],
                "pq_remove_unregistration_intent": {
                    "signature": pq_removal_step["pq_signature"],
                    "message": pq_removal_step["pq_message"]
                }
            })
        # Save to JSON file
        output_file = project_root / "test/test_vectors/unregister/unregistration_removal_vectors.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump({"remove_intent": remove_intent}, f, indent=2)
        print(f"Generated {len(remove_intent)} PQ removal vectors for unregistration flow with revocation")
        print(f"Output saved to: {output_file}")

    except Exception as e:
        print(f"Error generating vectors: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main() 
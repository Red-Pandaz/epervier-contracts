#!/usr/bin/env python3
"""
Generator for change ETH address flow with cancellation test vectors.
Scenario: PQ initiates change ETH intent → ETH cancels → PQ retries → ETH confirms
"""

import json
import sys
from pathlib import Path
from eth_account import Account
from eth_hash.auto import keccak
import os
import traceback

# Add the python directory to the path for EIP712 imports
sys.path.append(str(Path(__file__).resolve().parents[3] / "test" / "python"))
from eip712_helpers import get_change_eth_address_intent_struct_hash, get_change_eth_address_confirmation_struct_hash, get_remove_change_intent_struct_hash, sign_eip712_message

# Add the project root to the path
project_root = Path(__file__).parent.parent.parent.parent  # epervier-registry
sys.path.append(str(project_root))

DOMAIN_SEPARATOR = bytes.fromhex("5f5d847b41fe04c02ecf9746150300028bfc195e7981ae8fe39fe8b7a745650f")

def get_actor_config():
    config_file = project_root / "test" / "test_keys" / "actors_config.json"
    with open(config_file, 'r') as f:
        config = json.load(f)
        return config["actors"]

def create_base_eth_change_eth_address_intent_message(domain_separator, pq_fingerprint, new_eth_address, eth_nonce):
    pattern = b"Intent to change ETH Address and bind with Epervier Fingerprint "
    message = (
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +
        b" to " +
        bytes.fromhex(new_eth_address[2:]) +
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def create_pq_change_eth_address_intent_message(domain_separator, old_eth_address, new_eth_address, base_eth_message, v, r, s, pq_nonce):
    pattern = b"Intent to change bound ETH Address from "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(old_eth_address[2:]) +
        b" to " +
        bytes.fromhex(new_eth_address[2:]) +
        base_eth_message +
        v.to_bytes(1, 'big') +
        r.to_bytes(32, 'big') +
        s.to_bytes(32, 'big') +
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_eth_remove_change_intent_message(domain_separator, pq_fingerprint, eth_nonce):
    pattern = b"Remove change intent from Epervier Fingerprint "
    message = (
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def create_base_pq_change_eth_address_confirm_message(domain_separator, old_eth_address, new_eth_address, pq_nonce):
    pattern = b"Confirm changing bound ETH Address for Epervier Fingerprint from "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(old_eth_address[2:]) +
        b" to " +
        bytes.fromhex(new_eth_address[2:]) +
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_eth_change_eth_address_confirmation_message(domain_separator, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    pattern = b"Confirm change ETH Address for Epervier Fingerprint "
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    message = (
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +
        base_pq_message +
        salt +
        pack_uint256_array(cs1) +
        pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') +
        eth_nonce.to_bytes(32, 'big')
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

def generate_change_eth_flow_with_cancellation_vectors():
    vectors = []
    actors = get_actor_config()
    actor_names = list(actors.keys())
    for actor_name in actor_names:
        actor = actors[actor_name]
        print(f"Generating change ETH flow with cancellation vectors for {actor_name}...")
        old_eth_address = actor["eth_address"]
        pq_fingerprint = actor["pq_fingerprint"]
        pq_private_key_file = actor["pq_private_key_file"]
        eth_private_key = actor["eth_private_key"]
        # For this scenario, generate a new ETH address for the change
        new_eth_account = Account.create()
        new_eth_address = new_eth_account.address
        new_eth_private_key = new_eth_account.key.hex()
        # Step 1: PQ initiates change ETH intent (PQ nonce 0, ETH nonce 0)
        pq_nonce_0 = 0
        eth_nonce_0 = 0
        base_eth_message_0 = create_base_eth_change_eth_address_intent_message(DOMAIN_SEPARATOR, pq_fingerprint, new_eth_address, eth_nonce_0)
        eth_signature_0 = sign_eth_message(base_eth_message_0, new_eth_private_key)
        pq_message_0 = create_pq_change_eth_address_intent_message(
            DOMAIN_SEPARATOR, old_eth_address, new_eth_address, base_eth_message_0,
            eth_signature_0["v"], int(eth_signature_0["r"]), int(eth_signature_0["s"]), pq_nonce_0
        )
        pq_signature_0 = sign_pq_message(pq_message_0, pq_private_key_file)
        if pq_signature_0 is None:
            print(f"Failed to generate PQ signature for {actor_name} step 1")
            continue
        # Step 2: ETH cancels change intent (ETH nonce 1)
        eth_nonce_1 = 1
        eth_remove_message = create_eth_remove_change_intent_message(DOMAIN_SEPARATOR, pq_fingerprint, eth_nonce_1)
        eth_remove_signature = sign_eth_message(eth_remove_message, eth_private_key)
        # Step 3: PQ retries change ETH intent (PQ nonce 1, ETH nonce 2)
        pq_nonce_1 = 1
        eth_nonce_2 = 2
        base_eth_message_1 = create_base_eth_change_eth_address_intent_message(DOMAIN_SEPARATOR, pq_fingerprint, new_eth_address, eth_nonce_2)
        eth_signature_1 = sign_eth_message(base_eth_message_1, new_eth_private_key)
        pq_message_1 = create_pq_change_eth_address_intent_message(
            DOMAIN_SEPARATOR, old_eth_address, new_eth_address, base_eth_message_1,
            eth_signature_1["v"], int(eth_signature_1["r"]), int(eth_signature_1["s"]), pq_nonce_1
        )
        pq_signature_1 = sign_pq_message(pq_message_1, pq_private_key_file)
        if pq_signature_1 is None:
            print(f"Failed to generate PQ signature for {actor_name} step 3")
            continue
        # Step 4: ETH confirms change (ETH nonce 3, PQ nonce 2)
        eth_nonce_3 = 3
        pq_nonce_2 = 2
        base_pq_confirm_message = create_base_pq_change_eth_address_confirm_message(DOMAIN_SEPARATOR, old_eth_address, new_eth_address, pq_nonce_2)
        pq_confirm_signature = sign_pq_message(base_pq_confirm_message, pq_private_key_file)
        if pq_confirm_signature is None:
            print(f"Failed to generate PQ confirm signature for {actor_name}")
            continue
        eth_confirm_message = create_eth_change_eth_address_confirmation_message(
            DOMAIN_SEPARATOR, pq_fingerprint, base_pq_confirm_message,
            bytes.fromhex(pq_confirm_signature["salt"]),
            [int(x, 16) for x in pq_confirm_signature["cs1"]],
            [int(x, 16) for x in pq_confirm_signature["cs2"]],
            pq_confirm_signature["hint"], eth_nonce_3
        )
        eth_confirm_signature = sign_eth_message(eth_confirm_message, new_eth_private_key)
        scenario_vector = {
            "actor": actor_name,
            "old_eth_address": old_eth_address,
            "new_eth_address": new_eth_address,
            "pq_fingerprint": pq_fingerprint,
            "steps": [
                {
                    "step": 1,
                    "description": "PQ initiates change ETH intent",
                    "base_eth_message": base_eth_message_0.hex(),
                    "eth_signature": eth_signature_0,
                    "pq_message": pq_message_0.hex(),
                    "pq_signature": pq_signature_0,
                    "pq_nonce": pq_nonce_0,
                    "eth_nonce": eth_nonce_0
                },
                {
                    "step": 2,
                    "description": "ETH cancels change intent",
                    "eth_message": eth_remove_message.hex(),
                    "eth_signature": eth_remove_signature,
                    "eth_nonce": eth_nonce_1
                },
                {
                    "step": 3,
                    "description": "PQ retries change ETH intent",
                    "base_eth_message": base_eth_message_1.hex(),
                    "eth_signature": eth_signature_1,
                    "pq_message": pq_message_1.hex(),
                    "pq_signature": pq_signature_1,
                    "pq_nonce": pq_nonce_1,
                    "eth_nonce": eth_nonce_2
                },
                {
                    "step": 4,
                    "description": "ETH confirms change",
                    "base_pq_message": base_pq_confirm_message.hex(),
                    "pq_signature": pq_confirm_signature,
                    "eth_message": eth_confirm_message.hex(),
                    "eth_signature": eth_confirm_signature,
                    "pq_nonce": pq_nonce_2,
                    "eth_nonce": eth_nonce_3
                }
            ]
        }
        vectors.append(scenario_vector)
    return vectors

def main():
    print("Generating change ETH flow with cancellation test vectors...")
    try:
        vectors = generate_change_eth_flow_with_cancellation_vectors()
        # Convert to the standard format used by basic tests
        formatted_vectors = []
        for scenario in vectors:
            for step in scenario["steps"]:
                # Include all steps, not just those with eth_message
                formatted_vectors.append({
                    "actor": scenario["actor"],
                    "eth_address": scenario["old_eth_address"],
                    "pq_fingerprint": scenario["pq_fingerprint"],
                    "base_pq_message": step.get("base_pq_message", ""),
                    "pq_signature": step.get("pq_signature", {}),
                    "eth_message": step.get("eth_message", ""),
                    "eth_signature": step.get("eth_signature", {}),
                    "eth_nonce": step.get("eth_nonce", 0)
                })
        
        # Write to file in the same format as basic test vectors
        output_data = {
            "change_eth_flow_with_cancellation": formatted_vectors
        }
        
        output_file = "test/test_vectors_change-eth/change_eth_flow_with_cancellation_vectors.json"
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"Generated {len(formatted_vectors)} vectors for change ETH flow with cancellation")
        print(f"Output saved to: {output_file}")
        
    except Exception as e:
        print(f"Error generating vectors: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main() 
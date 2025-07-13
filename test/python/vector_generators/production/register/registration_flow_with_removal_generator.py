#!/usr/bin/env python3
"""
Generator for registration flow with removal test vectors.
Scenario: ETH creates intent → PQ removes → ETH creates new intent → PQ confirms
"""

import json
import sys
from pathlib import Path
from eth_account import Account
from eth_hash.auto import keccak
import os
import traceback

# Add the project root to the path
project_root = Path(__file__).parent.parent.parent.parent  # epervier-registry
sys.path.append(str(project_root))

# Add the python directory to the path for EIP712 imports
sys.path.append(str(project_root / "test" / "python"))

# Domain separator (same as in the contract)
DOMAIN_SEPARATOR = bytes.fromhex("5f5d847b41fe04c02ecf9746150300028bfc195e7981ae8fe39fe8b7a745650f")

# Import EIP712 helpers
from eip712_helpers import get_registration_intent_struct_hash, get_registration_confirmation_struct_hash, sign_eip712_message

def get_actor_config():
    """Load actor configuration from JSON file"""
    config_file = project_root / "test" / "test_keys" / "production_actors_config.json"
    with open(config_file, 'r') as f:
        config = json.load(f)
        return config["actors"]

def create_base_pq_registration_intent_message(domain_separator, eth_address, pq_nonce):
    """
    Create base PQ message for registration intent
    Format: DOMAIN_SEPARATOR + "Intent to pair ETH Address " + ethAddress + pqNonce
    """
    pattern = b"Intent to pair ETH Address "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(eth_address[2:]) +  # Remove "0x" prefix
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_eth_registration_intent_message(domain_separator, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    """
    Create ETH message for registration intent
    Format: "Intent to pair Epervier Key" + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
    (no domain separator in content for EIP712)
    """
    pattern = b"Intent to pair Epervier Key"
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    
    message = (
        pattern +
        base_pq_message +
        salt +
        pack_uint256_array(cs1) +
        pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') +
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def create_pq_remove_registration_intent_message(domain_separator, eth_address, pq_nonce):
    """
    Create PQ message for removing registration intent
    Format: DOMAIN_SEPARATOR + "Remove registration intent from ETH Address " + ethAddress + pqNonce
    """
    pattern = b"Remove registration intent from ETH Address "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(eth_address[2:]) +  # Remove "0x" prefix
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_base_eth_registration_confirmation_message(domain_separator, pq_fingerprint, eth_nonce):
    """
    Create base ETH message for registration confirmation
    Format: "Confirm bonding to Epervier Fingerprint " + pqFingerprint + ethNonce
    (no domain separator in content for EIP712)
    """
    pattern = b"Confirm bonding to Epervier Fingerprint "
    message = (
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def create_pq_registration_confirmation_message(domain_separator, eth_address, base_eth_message, v, r, s, pq_nonce):
    """
    Create PQ message for registration confirmation
    Format: DOMAIN_SEPARATOR + "Confirm bonding to ETH Address " + ethAddress + baseETHMessage + v + r + s + pqNonce
    """
    pattern = b"Confirm bonding to ETH Address "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(eth_address[2:]) +  # Remove "0x" prefix
        base_eth_message +
        v.to_bytes(1, 'big') +
        r.to_bytes(32, 'big') +
        s.to_bytes(32, 'big') +
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def sign_eth_message(message_bytes, private_key, message_type="registration_intent", **kwargs):
    """Sign a message with ETH private key using EIP712"""
    # Use EIP712 structured signing
    domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    
    if message_type == "registration_intent":
        struct_hash = get_registration_intent_struct_hash(
            kwargs["salt"], kwargs["cs1"], kwargs["cs2"], 
            kwargs["hint"], kwargs["base_pq_message"], kwargs["eth_nonce"]
        )
    elif message_type == "registration_confirmation":
        struct_hash = get_registration_confirmation_struct_hash(
            kwargs["pq_fingerprint"], kwargs["eth_nonce"]
        )
    else:
        raise ValueError(f"Unsupported message type: {message_type}")
    
    signature = sign_eip712_message(private_key, domain_separator, struct_hash)
    return signature

def sign_pq_message(message, pq_private_key_file):
    """Sign a message with PQ private key using sign_cli.py"""
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

def generate_registration_flow_with_removal_vectors():
    """Generate test vectors for registration flow with removal scenario"""
    vectors = []
    actors = get_actor_config()
    actor_names = list(actors.keys())

    for actor_name in actor_names:
        actor = actors[actor_name]
        print(f"Generating registration flow with removal vectors for {actor_name}...")

        eth_address = actor["eth_address"]
        pq_fingerprint = actor["pq_fingerprint"]

        # Step 1: Initial registration intent (ETH nonce 0, PQ nonce 0)
        eth_nonce_0 = 0
        pq_nonce_0 = 0
        
        base_pq_message_0 = create_base_pq_registration_intent_message(DOMAIN_SEPARATOR, eth_address, pq_nonce_0)
        pq_signature_0 = sign_pq_message(base_pq_message_0, actor["pq_private_key_file"])
        if pq_signature_0 is None:
            print(f"Failed to generate PQ signature for {actor_name} step 1")
            continue

        eth_message_0 = create_eth_registration_intent_message(
            DOMAIN_SEPARATOR, base_pq_message_0, 
            bytes.fromhex(pq_signature_0["salt"]), 
            [int(x, 16) for x in pq_signature_0["cs1"]], 
            [int(x, 16) for x in pq_signature_0["cs2"]], 
            pq_signature_0["hint"], eth_nonce_0
        )
        eth_signature_0 = sign_eth_message(
            eth_message_0, actor["eth_private_key"], 
            message_type="registration_intent",
            eth_nonce=eth_nonce_0,
            salt=bytes.fromhex(pq_signature_0["salt"]),
            cs1=[int(x, 16) for x in pq_signature_0["cs1"]],
            cs2=[int(x, 16) for x in pq_signature_0["cs2"]],
            hint=pq_signature_0["hint"],
            base_pq_message=base_pq_message_0
        )

        # Step 2: PQ removes registration intent (ETH nonce 0, PQ nonce 1)
        pq_nonce_1 = 1
        
        pq_remove_message = create_pq_remove_registration_intent_message(DOMAIN_SEPARATOR, eth_address, pq_nonce_1)
        pq_remove_signature = sign_pq_message(pq_remove_message, actor["pq_private_key_file"])
        if pq_remove_signature is None:
            print(f"Failed to generate PQ remove signature for {actor_name}")
            continue

        # Step 3: New registration intent (ETH nonce 1, PQ nonce 2)
        eth_nonce_1 = 1
        pq_nonce_2 = 2
        
        base_pq_message_1 = create_base_pq_registration_intent_message(DOMAIN_SEPARATOR, eth_address, pq_nonce_2)
        pq_signature_1 = sign_pq_message(base_pq_message_1, actor["pq_private_key_file"])
        if pq_signature_1 is None:
            print(f"Failed to generate PQ signature for {actor_name} step 3")
            continue

        eth_message_1 = create_eth_registration_intent_message(
            DOMAIN_SEPARATOR, base_pq_message_1, 
            bytes.fromhex(pq_signature_1["salt"]), 
            [int(x, 16) for x in pq_signature_1["cs1"]], 
            [int(x, 16) for x in pq_signature_1["cs2"]], 
            pq_signature_1["hint"], eth_nonce_1
        )
        eth_signature_1 = sign_eth_message(
            eth_message_1, actor["eth_private_key"], 
            message_type="registration_intent",
            eth_nonce=eth_nonce_1,
            salt=bytes.fromhex(pq_signature_1["salt"]),
            cs1=[int(x, 16) for x in pq_signature_1["cs1"]],
            cs2=[int(x, 16) for x in pq_signature_1["cs2"]],
            hint=pq_signature_1["hint"],
            base_pq_message=base_pq_message_1
        )

        # Step 4: Registration confirmation (ETH nonce 2, PQ nonce 3)
        eth_nonce_2 = 2
        pq_nonce_3 = 3
        
        base_eth_confirm_message = create_base_eth_registration_confirmation_message(DOMAIN_SEPARATOR, pq_fingerprint, eth_nonce_2)
        eth_confirm_signature = sign_eth_message(
            base_eth_confirm_message, actor["eth_private_key"],
            message_type="registration_confirmation",
            pq_fingerprint=pq_fingerprint,
            eth_nonce=eth_nonce_2
        )
        
        pq_confirm_message = create_pq_registration_confirmation_message(
            DOMAIN_SEPARATOR, eth_address, base_eth_confirm_message,
            eth_confirm_signature["v"], int(eth_confirm_signature["r"]), int(eth_confirm_signature["s"]), pq_nonce_3
        )
        pq_confirm_signature = sign_pq_message(pq_confirm_message, actor["pq_private_key_file"])
        if pq_confirm_signature is None:
            print(f"Failed to generate PQ confirm signature for {actor_name}")
            continue

        # Create the complete scenario vector
        scenario_vector = {
            "actor": actor_name,
            "eth_address": eth_address,
            "pq_fingerprint": pq_fingerprint,
            "steps": [
                {
                    "step": 1,
                    "description": "Initial registration intent",
                    "base_pq_message": base_pq_message_0.hex(),
                    "pq_signature": pq_signature_0,
                    "eth_message": eth_message_0.hex(),
                    "eth_signature": eth_signature_0,
                    "eth_nonce": eth_nonce_0,
                    "pq_nonce": pq_nonce_0
                },
                {
                    "step": 2,
                    "description": "PQ removes registration intent",
                    "pq_message": pq_remove_message.hex(),
                    "pq_signature": pq_remove_signature,
                    "pq_nonce": pq_nonce_1
                },
                {
                    "step": 3,
                    "description": "New registration intent",
                    "base_pq_message": base_pq_message_1.hex(),
                    "pq_signature": pq_signature_1,
                    "eth_message": eth_message_1.hex(),
                    "eth_signature": eth_signature_1,
                    "eth_nonce": eth_nonce_1,
                    "pq_nonce": pq_nonce_2
                },
                {
                    "step": 4,
                    "description": "Registration confirmation",
                    "base_eth_message": base_eth_confirm_message.hex(),
                    "eth_signature": eth_confirm_signature,
                    "pq_message": pq_confirm_message.hex(),
                    "pq_signature": pq_confirm_signature,
                    "eth_nonce": eth_nonce_2,
                    "pq_nonce": pq_nonce_3
                }
            ]
        }
        vectors.append(scenario_vector)

    return vectors

def main():
    print("Generating registration flow with removal test vectors...")
    try:
        vectors = generate_registration_flow_with_removal_vectors()
        
        # Convert to the exact format used by basic tests
        formatted_vectors = []
        
        for scenario in vectors:
            # Extract the registration intent step (first step)
            registration_step = None
            for step in scenario["steps"]:
                if step.get("step") == 1:  # First step is the registration intent
                    registration_step = step
                    break
            
            if registration_step:
                # Format exactly like basic tests expect
                formatted_vector = {
                    "actor": scenario["actor"],
                    "eth_address": scenario["eth_address"],
                    "pq_fingerprint": scenario["pq_fingerprint"],
                    "base_pq_message": registration_step["base_pq_message"],
                    "pq_signature": registration_step["pq_signature"],
                    "eth_message": registration_step["eth_message"],
                    "eth_signature": {
                        "v": registration_step["eth_signature"]["v"],
                        "r": registration_step["eth_signature"]["r"],  # Already integer
                        "s": registration_step["eth_signature"]["s"]   # Already integer
                    },
                    "eth_nonce": registration_step.get("eth_nonce", 0)
                }
                formatted_vectors.append(formatted_vector)
        
        # Create the final output structure exactly like basic tests
        output = {
            "registration_flow_with_removal": formatted_vectors
        }
        
        # Write to file
        output_path = Path("../../test/test_vectors/advanced/registration_flow_with_removal_vectors.json")
        # Ensure the directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"✅ Generated {len(formatted_vectors)} registration flow with removal vectors")
        print(f"📁 Saved to: {output_path}")
        
    except Exception as e:
        print(f"❌ Error generating vectors: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 
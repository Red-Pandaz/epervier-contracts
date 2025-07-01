#!/usr/bin/env python3

import json
import os
import subprocess
import sys
from pathlib import Path
from eth_utils import keccak

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

# Add the project root to the Python path
project_root = Path(__file__).resolve().parents[4]  # epervier-registry
sys.path.insert(0, str(project_root))

# Add ETHFALCON to the path for imports
sys.path.insert(0, str(project_root / "ETHFALCON" / "python-ref"))

# Add the python directory to the path for EIP712 imports
sys.path.append(str(Path(__file__).resolve().parents[2]))
from eip712_helpers import *
from eip712_config import *

print(f"DEBUG: project_root = {project_root}")
print(f"DEBUG: falcon path = {project_root / 'ETHFALCON' / 'python-ref'}")
print(f"DEBUG: falcon.py exists = {(project_root / 'ETHFALCON' / 'python-ref' / 'falcon.py').exists()}")
print(f"DEBUG: sys.path[0] = {sys.path[0]}")

# Constants and functions from registration_intent_generator
ACTORS_CONFIG_PATH = project_root / "test" / "test_keys" / "actors_config.json"

OUTPUT_PATH = project_root / "test/test_vectors/register/registration_confirmation_vectors.json"

def get_actor_config():
    """Load the actors config JSON."""
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]

def create_base_eth_message(pq_fingerprint, eth_nonce):
    """
    Create base ETH message for registration confirmation
    Format: "Confirm bonding to Epervier Fingerprint " + pqFingerprint + ethNonce
    This is signed by the ETH Address (no domain separator in content)
    """
    base_eth_pattern = "Confirm bonding to Epervier Fingerprint "
    message = (
        base_eth_pattern.encode() +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def generate_registration_confirmation_vector(actor_name):
    """Generate registration confirmation vector for a specific actor."""
    
    # Get actor configuration
    actors = get_actor_config()
    actor = actors[actor_name]
    
    print(f"Generating registration confirmation vector for {actor_name}...")
    
    # Load existing registration intent vectors to get the ETH message and signature
    intent_file = project_root / "test" / "test_vectors" / "register" / "registration_intent_vectors.json"
    with open(intent_file, 'r') as f:
        intent_data = json.load(f)
    
    # Find the intent vector for this actor
    intent_vector = None
    for intent in intent_data["registration_intent"]:
        if intent["actor"] == actor_name:
            intent_vector = intent
            break
    
    if not intent_vector:
        raise ValueError(f"No registration intent found for actor {actor_name}")
    
    # Get ETH nonce (should be 1 for confirmation after intent)
    eth_nonce = 1
    
    # Construct the BaseETHRegistrationConfirmationMessage according to schema
    # "Confirm bonding to Epervier Fingerprint " + pqFingerprint + ethNonce
    base_eth_message = create_base_eth_message(actor["pq_fingerprint"], eth_nonce)
    
    print(f"Generated base ETH message: {base_eth_message.hex()}")
    print(f"Length of base ETH message (bytes): {len(base_eth_message)}")
    
    # Generate ETH signature for the base ETH confirmation message
    # Load ETH private key and sign the base_eth_message
    eth_private_key_hex = actor["eth_private_key"]
    
    # Import eth_account for signing
    from eth_account import Account
    from eth_account.messages import encode_defunct
    
    # Create account from private key
    account = Account.from_key(eth_private_key_hex)
    
    # Sign the base ETH message using EIP712
    domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    struct_hash = get_registration_confirmation_struct_hash(actor["pq_fingerprint"], eth_nonce)
    
    # DEBUG: Print struct hash and EIP712 digest for comparison
    if actor_name == "alice":
        print(f"DEBUG: Struct hash for {actor_name}: {struct_hash.hex()}")
        eip712_digest = get_eip712_digest(domain_separator, struct_hash)
        print(f"DEBUG: EIP712 digest for {actor_name}: {eip712_digest.hex()}")
    
    # Use the same approach as the working registration intent
    from eth_utils import keccak
    digest = keccak(encode_packed(b'\x19\x01', domain_separator, struct_hash))
    sig = Account._sign_hash(digest, private_key=account.key)
    signature = {"v": sig.v, "r": sig.r, "s": sig.s}
    
    # Verify the signature by recovering the address from the signature
    recovered_address = Account._recover_hash(digest, vrs=(signature['v'], signature['r'], signature['s']))
    
    print(f"Generated ETH signature for confirmation: v={signature['v']}, r={hex(signature['r'])}, s={hex(signature['s'])}")
    print(f"ETH address from signature: {recovered_address}")
    print(f"Expected ETH address: {actor['eth_address']}")
    
    # Verify the signature matches the expected address
    if recovered_address.lower() != actor['eth_address'].lower():
        raise ValueError(f"ETH signature address mismatch: {recovered_address} vs {actor['eth_address']}")
    
    # Get PQ nonce (should be 1 for confirmation after intent)
    pq_nonce = 1
    
    # Construct the PQRegistrationConfirmationMessage according to schema
    # DOMAIN_SEPARATOR + "Confirm bonding to ETH Address " + ethAddress + baseETHMessage + v + r + s + pqNonce
    pattern = "Confirm bonding to ETH Address "
    eth_address_bytes = bytes.fromhex(actor["eth_address"][2:])  # Remove 0x prefix
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    
    # Build the message: DOMAIN_SEPARATOR + pattern + ethAddress + baseETHMessage + v + r + s + pqNonce
    message = (
        domain_separator_bytes +
        pattern.encode() +
        eth_address_bytes +
        base_eth_message +
        signature['v'].to_bytes(1, 'big') +
        signature['r'].to_bytes(32, 'big') +
        signature['s'].to_bytes(32, 'big') +
        pq_nonce.to_bytes(32, 'big')
    )
    
    print(f"Generated confirmation message: {message.hex()}")
    print(f"Length of confirmation message (bytes): {len(message)}")
    print(f"Expected length according to schema: 301 bytes")
    
    # Sign the message with PQ key
    pq_private_key_file = actor["pq_private_key_file"]
    
    # Create temporary message file
    message_file = f"/tmp/{actor_name}_confirmation_message.hex"
    with open(message_file, 'w') as f:
        f.write(message.hex())
    
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
            print(f"Failed to parse signature components for {actor_name}")
            return None
        
        # Create the confirmation vector
        confirmation_vector = {
            "actor": actor_name,
            "eth_address": actor["eth_address"],
            "pq_fingerprint": actor["pq_fingerprint"],
            "pq_message": message.hex(),
            "pq_signature": {
                "salt": signature_data["salt"].hex(),
                "hint": signature_data["hint"],
                "cs1": [hex(x) for x in signature_data["cs1"]],
                "cs2": [hex(x) for x in signature_data["cs2"]]
            }
        }
        
        return confirmation_vector
        
    finally:
        # Clean up temporary files
        if os.path.exists(message_file):
            os.remove(message_file)

def main():
    """Generate registration confirmation vectors for all actors."""
    
    # Get actor configuration
    actors = get_actor_config()
    
    # Generate confirmation vectors for all actors
    confirmation_vectors = []
    for actor_name in actors.keys():
        try:
            confirmation_vector = generate_registration_confirmation_vector(actor_name)
            if confirmation_vector:
                confirmation_vectors.append(confirmation_vector)
                print(f"✓ Generated confirmation vector for {actor_name}")
            else:
                print(f"✗ Failed to generate confirmation vector for {actor_name}")
        except Exception as e:
            print(f"✗ Error generating confirmation vector for {actor_name}: {e}")
    
    # Write confirmation vectors to the correct file
    confirmation_data = {"registration_confirmation": confirmation_vectors}
    
    # Write vectors to output file
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(confirmation_data, f, indent=2)
    
    print(f"\nGenerated {len(confirmation_vectors)} registration confirmation vectors")
    print(f"Updated {OUTPUT_PATH}")

if __name__ == "__main__":
    main() 
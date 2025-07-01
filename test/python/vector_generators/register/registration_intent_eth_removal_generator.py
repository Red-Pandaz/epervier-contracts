#!/usr/bin/env python3
"""
Generator for cancel registration intent test vectors.
"""

import json
import sys
from pathlib import Path
from eth_account import Account
from eth_hash.auto import keccak
from eth_abi import encode

# Add the project root to the path
project_root = Path(__file__).resolve().parents[4]  # epervier-registry
sys.path.append(str(project_root))

# Add the python directory to the path for EIP712 imports
sys.path.append(str(Path(__file__).resolve().parents[2]))
from eip712_helpers import *
from eip712_config import *

print("Script loaded successfully!")

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

def get_actor_config():
    """Load actor configuration from JSON file"""
    config_file = project_root / "test/test_keys/actors_config.json"
    with open(config_file, 'r') as f:
        config = json.load(f)
        return config["actors"]

def create_remove_registration_message(pq_fingerprint, eth_nonce):
    """
    Create structured string message for removing registration intent
    Format: "Remove registration intent from Epervier Fingerprint " + pqFingerprint + ethNonce
    This matches the contract's parseETHRemoveRegistrationIntentMessage expectations
    """
    pattern = b"Remove registration intent from Epervier Fingerprint "
    # Convert pq_fingerprint from hex string to bytes (20 bytes)
    pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])  # Remove '0x' prefix
    # Convert eth_nonce to 32 bytes
    eth_nonce_bytes = eth_nonce.to_bytes(32, 'big')
    
    message = pattern + pq_fingerprint_bytes + eth_nonce_bytes
    return message

def sign_eth_message(message, eth_private_key, pq_fingerprint, eth_nonce):
    """Sign the EIP-712 digest with ETH private key"""
    from eth_account import Account
    from eth_utils import keccak
    from eth_abi import encode
    
    # Create the struct hash for RemoveIntent using abi.encode (same as contract)
    type_hash = keccak(b"RemoveIntent(address pqFingerprint,uint256 ethNonce)")
    struct_hash = keccak(encode([
        'bytes32',
        'address', 
        'uint256'
    ], [
        type_hash,
        pq_fingerprint,  # address (20 bytes)
        eth_nonce        # uint256
    ]))
    
    # Create EIP-712 digest with domain separator
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    digest = keccak(b'\x19\x01' + domain_separator_bytes + struct_hash)
    
    # Sign the digest
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    return {
        "v": sig.v,
        "r": sig.r,
        "s": sig.s,
        "signature": sig.signature.hex()
    }

def generate_remove_registration_intent_vectors():
    """Generate test vectors for removing registration intents for all 10 actors"""
    remove_vectors = []
    actors = get_actor_config()
    actor_names = list(actors.keys())
    num_actors = len(actor_names)

    for i in range(num_actors):
        current_actor_name = actor_names[i]
        current_actor = actors[current_actor_name]

        print(f"Generating remove registration intent vector for {current_actor_name}...")

        eth_address = current_actor["eth_address"]
        pq_fingerprint = current_actor["pq_fingerprint"]
        eth_private_key = current_actor["eth_private_key"]

        # Nonces for remove operation
        eth_nonce = 1  # ETH nonce for remove operation

        # Create the ETH remove message and sign it with ETH key
        eth_message = create_remove_registration_message(pq_fingerprint, eth_nonce)
        eth_signature = sign_eth_message(eth_message, eth_private_key, pq_fingerprint, eth_nonce)
        
        if eth_signature is None:
            print(f"Failed to generate ETH signature for {current_actor_name}")
            continue

        remove_vector = {
            "current_actor": current_actor_name,
            "eth_address": eth_address,
            "pq_fingerprint": pq_fingerprint,
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "eth_nonce": eth_nonce
        }
        remove_vectors.append(remove_vector)

    return remove_vectors

def main():
    """Main function to generate and save test vectors"""
    print("Generating remove registration intent test vectors...")
    
    try:
        vectors = generate_remove_registration_intent_vectors()
        
        # Save to JSON file
        output_file = project_root / "test/test_vectors/register/registration_eth_removal_vectors.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump({"registration_eth_removal": vectors}, f, indent=2)
        
        print(f"Generated {len(vectors)} remove registration intent vectors")
        print(f"Vectors saved to {output_file}")
        
        # Print sample vector for verification
        if vectors:
            print("\nSample remove registration intent vector:")
            vector = vectors[0]
            print(f"Current Actor: {vector['current_actor']}")
            print(f"ETH Address: {vector['eth_address']}")
            print(f"PQ Fingerprint: {vector['pq_fingerprint']}")
            print(f"ETH Nonce: {vector['eth_nonce']}")
        
    except Exception as e:
        print(f"Error generating vectors: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
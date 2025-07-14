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
project_root = Path(__file__).parent.parent.parent.parent.parent  # epervier-registry
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
    Create base ETH message for change ETH Address intent
    Format: DOMAIN_SEPARATOR + "Intent to change ETH Address and bind with Epervier Fingerprint " + pqFingerprint + " to " + newEthAddress + ethNonce
    This is signed by Bob (new ETH Address)
    """
    pattern = b"Intent to change ETH Address and bind with Epervier Fingerprint "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        b" to " +
        bytes.fromhex(new_eth_address[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def create_base_pq_message(domain_separator, old_eth_address, new_eth_address, base_eth_message, v, r, s, pq_nonce):
    """
    Create base PQ message for change ETH Address intent
    Format: DOMAIN_SEPARATOR + "Intent to change bound ETH Address from " + oldEthAddress + " to " + newEthAddress + baseETHMessage + v + r + s + pqNonce
    This is signed by Alice (PQ key)
    """
    pattern = b"Intent to change bound ETH Address from "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(old_eth_address[2:]) +  # Remove "0x" prefix
        b" to " +
        bytes.fromhex(new_eth_address[2:]) +  # Remove "0x" prefix
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
        "r": hex(sig.r),
        "s": hex(sig.s)
    }

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

def create_eth_remove_message(domain_separator, pq_fingerprint, eth_nonce):
    """
    Create ETH message for removing change ETH address intent
    Format: DOMAIN_SEPARATOR + "Remove change intent from Epervier Fingerprint " + pqFingerprint + ethNonce
    This is signed by the ETH key
    """
    pattern = b"Remove change intent from Epervier Fingerprint "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, "big")
    )
    return message

def create_pq_remove_message(domain_separator, eth_address, pq_nonce):
    """
    Create PQ message for removing change ETH address intent
    Format: DOMAIN_SEPARATOR + "Remove change intent from ETH Address " + ethAddress + pqNonce
    This is signed by the PQ key
    """
    pattern = b"Remove change intent from ETH Address "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(eth_address[2:]) +  # Remove "0x" prefix
        pq_nonce.to_bytes(32, "big")
    )
    return message

def generate_change_eth_address_intent_vectors():
    """Generate test vectors for advanced change ETH address scenarios"""
    
    change_intent_vectors = []
    actors = get_actor_config()
    
    # Test 4: PQ cancels change ETH intent (alice -> bob -> charlie)
    print("Generating Test 4: PQ cancels change ETH intent (alice -> bob -> charlie)...")
    
    alice = actors["alice"]
    bob = actors["bob"]
    charlie = actors["charlie"]
    
    # Create placeholder vectors for indices 0 and 1 (not used by test)
    placeholder_vector = {
        "current_actor": "placeholder",
        "new_actor": "placeholder",
        "old_eth_address": "0x0000000000000000000000000000000000000000",
        "new_eth_address": "0x0000000000000000000000000000000000000000",
        "pq_fingerprint": "0x0000000000000000000000000000000000000000",
        "pq_message": "0x",
        "pq_signature": {"salt": "0x", "hint": 0, "cs1": [], "cs2": []},
        "pq_nonce": 0,
        "eth_nonce": 0
    }
    
    # Create a list with 6 elements (indices 0-5)
    test4_vectors = [placeholder_vector] * 6  # Initialize all as placeholders
    
    # Step 2: Alice submits change intent to Bob (PQ intent) - index 2
    print("  Generating Step 2: Change intent to Bob...")
    old_eth_address = alice["eth_address"]  # Alice's ETH address
    new_eth_address = bob["eth_address"]     # Bob's ETH address
    pq_fingerprint = alice["pq_fingerprint"] # Alice's PQ fingerprint
    
    # Nonces
    eth_nonce = 0  # Bob's ETH nonce (always 0 for new actor)
    pq_nonce = 2   # Alice's PQ nonce (2 for change ETH address intent after registration)
    
    # Step 1: Bob signs the base ETH message
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, pq_fingerprint, new_eth_address, eth_nonce)
    eth_signature = sign_eth_message(base_eth_message, bob["eth_private_key"])  # Bob signs
    
    # Step 2: Alice's PQ key signs the complete message containing Bob's signature
    base_pq_message = create_base_pq_message(
        DOMAIN_SEPARATOR, old_eth_address, new_eth_address, base_eth_message,
        eth_signature["v"], int(eth_signature["r"], 16), int(eth_signature["s"], 16), pq_nonce)
    pq_signature = sign_pq_message(base_pq_message, alice["pq_private_key_file"])  # Alice's PQ key signs
    
    if pq_signature is None:
        print("Failed to generate PQ signature for step 2")
        return None
    
    # Create vector for step 2 (index 2)
    step2_vector = {
        "current_actor": "alice",
        "new_actor": "bob",
        "old_eth_address": old_eth_address,
        "new_eth_address": new_eth_address,
        "pq_fingerprint": pq_fingerprint,
        "base_eth_message": base_eth_message.hex(),
        "pq_message": base_pq_message.hex(),
        "eth_message": base_pq_message.hex(),  # For contract submission
        "eth_signature": eth_signature,
        "pq_signature": pq_signature,
        "eth_nonce": eth_nonce,
        "pq_nonce": pq_nonce
    }
    test4_vectors[2] = step2_vector  # Put at index 2
    
    # Step 3: PQ cancels the change intent - index 3
    print("  Generating Step 3: PQ cancels change intent...")
    old_eth_address = alice["eth_address"]  # Alice's ETH address
    
    # Nonces
    pq_nonce = 3   # Alice's PQ nonce (3 for PQ cancel after change intent)
    
    # Create PQ removal message
    pq_message = create_pq_remove_message(DOMAIN_SEPARATOR, old_eth_address, pq_nonce)
    pq_signature = sign_pq_message(pq_message, alice["pq_private_key_file"])  # Alice's PQ key signs
    
    if pq_signature is None:
        print("Failed to generate PQ signature for step 3")
        return None
    
    # Create vector for step 3
    step3_vector = {
        "current_actor": "alice",
        "new_actor": "bob",
        "old_eth_address": old_eth_address,
        "new_eth_address": bob["eth_address"],
        "pq_fingerprint": alice["pq_fingerprint"],
        "pq_message": pq_message.hex(),
        "pq_signature": pq_signature,
        "pq_nonce": pq_nonce,
        "eth_nonce": 0
    }
    test4_vectors[3] = step3_vector  # Put at index 3
    
    # Step 4: Alice submits change intent to Charlie (PQ intent) - index 4
    print("  Generating Step 4: Change intent to Charlie...")
    new_eth_address = charlie["eth_address"]     # Charlie's ETH address
    
    # Nonces
    eth_nonce = 0  # Charlie's ETH nonce (always 0 for new actor)
    pq_nonce = 3   # Alice's PQ nonce (3 for change ETH address intent after cancellation)
    
    # Step 1: Charlie signs the base ETH message
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, pq_fingerprint, new_eth_address, eth_nonce)
    eth_signature = sign_eth_message(base_eth_message, charlie["eth_private_key"])  # Charlie signs
    
    # Step 2: Alice's PQ key signs the complete message containing Charlie's signature
    base_pq_message = create_base_pq_message(
        DOMAIN_SEPARATOR, old_eth_address, new_eth_address, base_eth_message,
        eth_signature["v"], int(eth_signature["r"], 16), int(eth_signature["s"], 16), pq_nonce)
    pq_signature = sign_pq_message(base_pq_message, alice["pq_private_key_file"])  # Alice's PQ key signs
    
    if pq_signature is None:
        print(f"Failed to generate PQ signature for Test 4 Step 4")
        return None
    
    # Create the full ETH message for contract submission
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
        b"Intent to change ETH Address and bind with Epervier Fingerprint " +
        bytes.fromhex(pq_fingerprint[2:]) +
        base_pq_message_for_contract +
        bytes.fromhex(pq_signature["salt"]) +
        b''.join([x.to_bytes(32, 'big') for x in [int(cs, 16) for cs in pq_signature["cs1"]]]) +
        b''.join([x.to_bytes(32, 'big') for x in [int(cs, 16) for cs in pq_signature["cs2"]]]) +
        pq_signature["hint"].to_bytes(32, 'big') +
        eth_nonce.to_bytes(32, 'big')
    )
    
    test4_step4_vector = {
        "current_actor": "alice",
        "new_actor": "charlie",
        "old_eth_address": old_eth_address,
        "new_eth_address": new_eth_address,
        "pq_fingerprint": pq_fingerprint,
        "base_eth_message": base_eth_message.hex(),
        "pq_message": base_pq_message.hex(),
        "eth_message": eth_message.hex(),
        "eth_signature": eth_signature,
        "pq_signature": pq_signature,
        "eth_nonce": eth_nonce,
        "pq_nonce": pq_nonce
    }
    
    test4_vectors[4] = test4_step4_vector  # Put at index 4
    
    # Step 5: Charlie confirms change to Charlie (ETH confirmation) - index 5
    print("  Generating Step 5: ETH confirms change to Charlie...")
    # This is the same as Step 4 but used for confirmation
    test4_step5_vector = test4_step4_vector.copy()
    test4_vectors[5] = test4_step5_vector  # Put at index 5
    
    # Test 5: ETH cancels change ETH intent (alice -> bob -> charlie)
    print("Generating Test 5: ETH cancels change ETH intent (alice -> bob -> charlie)...")
    
    # Add placeholders for indices 0 and 1
    test5_vectors = [placeholder_vector] * 6  # Initialize all as placeholders
    
    # Step 2: Alice submits change intent to Bob (PQ intent) - index 2
    print("  Generating Step 2: Change intent to Bob...")
    old_eth_address = alice["eth_address"]  # Alice's ETH address
    new_eth_address = bob["eth_address"]     # Bob's ETH address
    pq_fingerprint = alice["pq_fingerprint"] # Alice's PQ fingerprint
    
    # Nonces
    eth_nonce = 0  # Bob's ETH nonce (always 0 for new actor)
    pq_nonce = 2   # Alice's PQ nonce (2 for change ETH address intent after registration)
    
    # Step 1: Bob signs the base ETH message
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, pq_fingerprint, new_eth_address, eth_nonce)
    eth_signature = sign_eth_message(base_eth_message, bob["eth_private_key"])  # Bob signs
    
    # Step 2: Alice's PQ key signs the complete message containing Bob's signature
    base_pq_message = create_base_pq_message(
        DOMAIN_SEPARATOR, old_eth_address, new_eth_address, base_eth_message,
        eth_signature["v"], int(eth_signature["r"], 16), int(eth_signature["s"], 16), pq_nonce)
    pq_signature = sign_pq_message(base_pq_message, alice["pq_private_key_file"])  # Alice's PQ key signs
    
    if pq_signature is None:
        print(f"Failed to generate PQ signature for Test 5 Step 2")
        return None
    
    # Create the full ETH message for contract submission
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
        b"Intent to change ETH Address and bind with Epervier Fingerprint " +
        bytes.fromhex(pq_fingerprint[2:]) +
        base_pq_message_for_contract +
        bytes.fromhex(pq_signature["salt"]) +
        b''.join([x.to_bytes(32, 'big') for x in [int(cs, 16) for cs in pq_signature["cs1"]]]) +
        b''.join([x.to_bytes(32, 'big') for x in [int(cs, 16) for cs in pq_signature["cs2"]]]) +
        pq_signature["hint"].to_bytes(32, 'big') +
        eth_nonce.to_bytes(32, 'big')
    )
    
    test5_step2_vector = {
        "current_actor": "alice",
        "new_actor": "bob",
        "old_eth_address": old_eth_address,
        "new_eth_address": new_eth_address,
        "pq_fingerprint": pq_fingerprint,
        "base_eth_message": base_eth_message.hex(),
        "pq_message": base_pq_message.hex(),
        "eth_message": eth_message.hex(),
        "eth_signature": eth_signature,
        "pq_signature": pq_signature,
        "eth_nonce": eth_nonce,
        "pq_nonce": pq_nonce
    }
    
    test5_vectors[2] = test5_step2_vector  # Put at index 2
    
    # Step 3: ETH cancels the change intent - index 3
    print("  Generating Step 3: ETH cancels change intent...")
    pq_fingerprint = alice["pq_fingerprint"]  # Alice's PQ fingerprint
    
    # Nonces
    eth_nonce = 1  # Bob's ETH nonce (1 for ETH cancel)
    
    # Create ETH removal message
    eth_message = create_eth_remove_message(DOMAIN_SEPARATOR, pq_fingerprint, eth_nonce)
    eth_signature = sign_eth_message(eth_message, bob["eth_private_key"])  # Bob's ETH key signs
    
    # Create vector for step 3
    step3_vector = {
        "current_actor": "alice",
        "new_actor": "bob",
        "old_eth_address": alice["eth_address"],
        "new_eth_address": bob["eth_address"],
        "pq_fingerprint": alice["pq_fingerprint"],
        "eth_message": eth_message.hex(),
        "eth_signature": eth_signature,
        "pq_nonce": 2,  # Alice's PQ nonce stays at 2 after ETH cancel
        "eth_nonce": eth_nonce
    }
    test5_vectors[3] = step3_vector  # Put at index 3
    
    # Step 4: Alice submits change intent to Charlie (PQ intent) - index 4
    print("  Generating Step 4: Change intent to Charlie...")
    new_eth_address = charlie["eth_address"]     # Charlie's ETH address
    
    # Nonces
    eth_nonce = 0  # Charlie's ETH nonce (always 0 for new actor)
    pq_nonce = 2   # Alice's PQ nonce (still 2 after ETH cancel - no increment)
    
    # Step 1: Charlie signs the base ETH message
    base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, pq_fingerprint, new_eth_address, eth_nonce)
    eth_signature = sign_eth_message(base_eth_message, charlie["eth_private_key"])  # Charlie signs
    
    # Step 2: Alice's PQ key signs the complete message containing Charlie's signature
    base_pq_message = create_base_pq_message(
        DOMAIN_SEPARATOR, old_eth_address, new_eth_address, base_eth_message,
        eth_signature["v"], int(eth_signature["r"], 16), int(eth_signature["s"], 16), pq_nonce)
    pq_signature = sign_pq_message(base_pq_message, alice["pq_private_key_file"])  # Alice's PQ key signs
    
    if pq_signature is None:
        print(f"Failed to generate PQ signature for Test 5 Step 4")
        return None
    
    # Create the full ETH message for contract submission
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
        b"Intent to change ETH Address and bind with Epervier Fingerprint " +
        bytes.fromhex(pq_fingerprint[2:]) +
        base_pq_message_for_contract +
        bytes.fromhex(pq_signature["salt"]) +
        b''.join([x.to_bytes(32, 'big') for x in [int(cs, 16) for cs in pq_signature["cs1"]]]) +
        b''.join([x.to_bytes(32, 'big') for x in [int(cs, 16) for cs in pq_signature["cs2"]]]) +
        pq_signature["hint"].to_bytes(32, 'big') +
        eth_nonce.to_bytes(32, 'big')
    )
    
    test5_step4_vector = {
        "current_actor": "alice",
        "new_actor": "charlie",
        "old_eth_address": old_eth_address,
        "new_eth_address": new_eth_address,
        "pq_fingerprint": pq_fingerprint,
        "base_eth_message": base_eth_message.hex(),
        "pq_message": base_pq_message.hex(),
        "eth_message": eth_message.hex(),
        "eth_signature": eth_signature,
        "pq_signature": pq_signature,
        "eth_nonce": eth_nonce,
        "pq_nonce": pq_nonce
    }
    
    test5_vectors[4] = test5_step4_vector  # Put at index 4
    
    # Step 5: Alice confirms change to Charlie (ETH confirmation) - index 5
    print("  Generating Step 5: ETH confirms change to Charlie...")
    # This is the same as Step 4 but used for confirmation
    test5_step5_vector = test5_step4_vector.copy()
    test5_vectors[5] = test5_step5_vector  # Put at index 5
    
    return test4_vectors + test5_vectors

def main():
    """Main function to generate and save vectors"""
    print("Generating advanced change ETH address vectors using working format...")
    
    vectors = generate_change_eth_address_intent_vectors()
    
    if vectors is None:
        print("Failed to generate vectors")
        return
    
    # Create output directory
    output_dir = project_root / "test" / "test_vectors" / "advanced"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save Test 4 vectors (PQ cancels change ETH intent) - first 6 vectors
    test4_file = output_dir / "test4_pq_cancels_change_eth_vectors.json"
    with open(test4_file, 'w') as f:
        json.dump({"vectors": vectors[:6]}, f, indent=2)
    print(f"Saved Test 4 vectors to: {test4_file}")
    
    # Save Test 5 vectors (ETH cancels change ETH intent) - remaining 6 vectors
    test5_file = output_dir / "test5_eth_cancels_change_eth_vectors.json"
    with open(test5_file, 'w') as f:
        json.dump({"vectors": vectors[6:]}, f, indent=2)
    print(f"Saved Test 5 vectors to: {test5_file}")
    
    print("Advanced vector generation complete!")

if __name__ == "__main__":
    main() 
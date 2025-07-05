#!/usr/bin/env python3
"""
Change ETH Address Revert Test Vector Generator

This generator creates test vectors specifically designed to trigger revert conditions
in the PQRegistry contract's change ETH address functionality.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, List
from eth_account import Account
from eth_utils import keccak
import subprocess
import re

# Add the parent directory to the path to import eip712_config
sys.path.append(str(Path(__file__).resolve().parents[2]))  # test/python
from eip712_config import DOMAIN_SEPARATOR
from eip712_helpers import (
    get_change_eth_address_intent_struct_hash,
    get_eip712_digest,
    sign_eip712_message,
)

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[4]  # epervier-registry
ACTORS_CONFIG_PATH = PROJECT_ROOT / "test" / "test_keys" / "actors_config.json"
OUTPUT_PATH = PROJECT_ROOT / "test/test_vectors/revert"

def load_actors_config():
    # Load the actors config JSON
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]

def sign_with_pq_key(base_pq_message, pq_private_key_file):
    """Sign a message with PQ private key using sign_cli.py"""
    try:
        # Sign with PQ key using sign_cli.py
        sign_cli = str(PROJECT_ROOT / "ETHFALCON" / "python-ref" / "sign_cli.py")
        privkey_path = str(PROJECT_ROOT / "test" / "test_keys" / pq_private_key_file)
        venv_python = str(PROJECT_ROOT / "ETHFALCON" / "python-ref" / "myenv" / "bin" / "python3")
        
        cmd = [
            venv_python, sign_cli, "sign",
            f"--privkey={privkey_path}",
            f"--data={base_pq_message.hex()}",
            "--version=epervier"
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT / "ETHFALCON" / "python-ref")
        
        if result.returncode != 0:
            print(f"Error signing message: {result.stderr}")
            return None
        
        print(f"PQ sign_cli output:")
        print(result.stdout)
        
        # Parse the signature components from stdout
        lines = result.stdout.splitlines()
        signature_data = {}
        try:
            i = 0
            while i < len(lines):
                line = lines[i]
                
                if line.startswith("salt:"):
                    signature_data["salt"] = bytes.fromhex(line.split()[1])
                    i += 1
                elif line.startswith("hint:"):
                    signature_data["hint"] = int(line.split()[1])
                    i += 1
                elif line.startswith("cs1:"):
                    # Collect all cs1 values across multiple lines
                    cs1_content = line[4:].strip()  # Remove "cs1:" prefix
                    i += 1
                    # Continue reading lines until we hit another key or end
                    while i < len(lines) and not lines[i].startswith(("salt:", "hint:", "cs1:", "cs2:")):
                        cs1_content += " " + lines[i].strip()
                        i += 1
                    
                    # Parse the collected cs1 values
                    values = cs1_content.split()
                    parsed = []
                    for x in values:
                        if x and re.match(r'^0x[0-9a-fA-F]+$', x):
                            try:
                                parsed.append(int(x[2:], 16))
                            except Exception as e:
                                print(f"Error parsing cs1 value '{x}': {e}")
                        elif x:
                            print(f"Skipping non-hex cs1 value: '{x}'")
                    signature_data["cs1"] = parsed
                    
                elif line.startswith("cs2:"):
                    # Collect all cs2 values across multiple lines
                    cs2_content = line[4:].strip()  # Remove "cs2:" prefix
                    i += 1
                    # Continue reading lines until we hit another key or end
                    while i < len(lines) and not lines[i].startswith(("salt:", "hint:", "cs1:", "cs2:")):
                        cs2_content += " " + lines[i].strip()
                        i += 1
                    
                    # Parse the collected cs2 values
                    values = cs2_content.split()
                    parsed = []
                    for x in values:
                        if x and re.match(r'^0x[0-9a-fA-F]+$', x):
                            try:
                                parsed.append(int(x[2:], 16))
                            except Exception as e:
                                print(f"Error parsing cs2 value '{x}': {e}")
                        elif x:
                            print(f"Skipping non-hex cs2 value: '{x}'")
                    signature_data["cs2"] = parsed
                else:
                    i += 1
        except Exception as e:
            print(f"Exception during PQ signature parsing: {e}")
            return None
        
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

class ChangeETHRevertGenerator:
    def __init__(self):
        self.actors = load_actors_config()
        
    def create_base_eth_message(self, pq_fingerprint, new_eth_address, eth_nonce):
        """
        Create base ETH message for change ETH Address intent
        Format: "Intent to change ETH Address and bond with Epervier Fingerprint " + pqFingerprint + " to " + newEthAddress + ethNonce
        This is signed by the new ETH Address (no domain separator in content)
        """
        pattern = b"Intent to change ETH Address and bond with Epervier Fingerprint "
        message = (
            pattern +
            bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
            b" to " +
            bytes.fromhex(new_eth_address[2:]) +  # Remove "0x" prefix
            eth_nonce.to_bytes(32, 'big')
        )
        return message

    def create_base_pq_message(self, old_eth_address, new_eth_address, base_eth_message, v, r, s, pq_nonce):
        """
        Create base PQ message for change ETH Address intent
        Format: DOMAIN_SEPARATOR + "Intent to change bound ETH Address from " + oldEthAddress + " to " + newEthAddress + baseETHMessage + v + r + s + pqNonce
        This matches the contract's parsePQChangeETHAddressIntentMessage function exactly
        """
        domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix, 32 bytes
        pattern = b"Intent to change bound ETH Address from "
        old_addr_bytes = bytes.fromhex(old_eth_address[2:])  # Remove "0x" prefix, 20 bytes
        to_pattern = b" to "
        new_addr_bytes = bytes.fromhex(new_eth_address[2:])  # Remove "0x" prefix, 20 bytes
        
        # Convert base_eth_message from hex string to bytes
        if isinstance(base_eth_message, bytes):
            base_eth_message_str = base_eth_message.hex()
        else:
            base_eth_message_str = base_eth_message

        base_eth_message_bytes = bytes.fromhex(base_eth_message_str[2:] if base_eth_message_str.startswith('0x') else base_eth_message_str)
        
        # Pad or truncate base_eth_message_bytes to exactly 140 bytes
        if len(base_eth_message_bytes) < 140:
            base_eth_message_bytes = base_eth_message_bytes + b'\x00' * (140 - len(base_eth_message_bytes))
        elif len(base_eth_message_bytes) > 140:
            base_eth_message_bytes = base_eth_message_bytes[:140]
        
        # Convert signature components to bytes
        v_bytes = v.to_bytes(1, 'big')  # 1 byte
        r_bytes = r.to_bytes(32, 'big')  # 32 bytes
        s_bytes = s.to_bytes(32, 'big')  # 32 bytes
        pq_nonce_bytes = pq_nonce.to_bytes(32, 'big')  # 32 bytes
        
        # Concatenate all components with DOMAIN_SEPARATOR at the start
        message = domain_separator_bytes + pattern + old_addr_bytes + to_pattern + new_addr_bytes + base_eth_message_bytes + v_bytes + r_bytes + s_bytes + pq_nonce_bytes
        
        return message

    def sign_eth_message(self, new_eth_address, pq_fingerprint, eth_nonce, private_key):
        """Sign the change ETH address intent message using EIP712"""
        # Get the struct hash using the same pattern as the working generator
        struct_hash = get_change_eth_address_intent_struct_hash(
            new_eth_address, pq_fingerprint, eth_nonce
        )
        
        # Get the EIP712 digest
        domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
        digest = get_eip712_digest(domain_separator_bytes, struct_hash)
        
        # Sign the digest
        signature = sign_eip712_message(digest, private_key)
        
        return signature

    def generate_wrong_domain_separator_pq_message(self, current_actor, new_actor, test_name, description):
        """Generate a change ETH intent vector with wrong domain separator in PQ message"""
        current = self.actors[current_actor]
        new = self.actors[new_actor]
        
        # Use correct nonces
        current_pq_nonce = 2  # Current actor used nonce 0 for registration, 1 for confirmation
        new_eth_nonce = 0     # New actor first time being used
        
        # Step 1: New actor signs the base ETH message
        base_eth_message = self.create_base_eth_message(current["pq_fingerprint"], new["eth_address"], new_eth_nonce)
        eth_signature = self.sign_eth_message(new["eth_address"], current["pq_fingerprint"], new_eth_nonce, new["eth_private_key"])
        
        # Step 2: Create PQ message with WRONG domain separator
        wrong_domain_separator = "0x" + "00" * 32  # All zeros instead of correct domain separator
        pattern = b"Intent to change bound ETH Address from "
        old_addr_bytes = bytes.fromhex(current["eth_address"][2:])
        to_pattern = b" to "
        new_addr_bytes = bytes.fromhex(new["eth_address"][2:])
        base_eth_message_bytes = bytes.fromhex(base_eth_message.hex()[2:])
        
        # Pad or truncate base_eth_message_bytes to exactly 140 bytes
        if len(base_eth_message_bytes) < 140:
            base_eth_message_bytes = base_eth_message_bytes + b'\x00' * (140 - len(base_eth_message_bytes))
        elif len(base_eth_message_bytes) > 140:
            base_eth_message_bytes = base_eth_message_bytes[:140]
        
        # Convert signature components to bytes
        v_bytes = eth_signature["v"].to_bytes(1, 'big')
        r_bytes = eth_signature["r"].to_bytes(32, 'big')
        s_bytes = eth_signature["s"].to_bytes(32, 'big')
        pq_nonce_bytes = current_pq_nonce.to_bytes(32, 'big')
        
        # Create message with WRONG domain separator
        wrong_domain_separator_bytes = bytes.fromhex(wrong_domain_separator[2:])
        base_pq_message = wrong_domain_separator_bytes + pattern + old_addr_bytes + to_pattern + new_addr_bytes + base_eth_message_bytes + v_bytes + r_bytes + s_bytes + pq_nonce_bytes
        
        # Sign with PQ key
        pq_signature = sign_with_pq_key(base_pq_message, current["pq_private_key_file"])
        
        if pq_signature is None:
            print(f"Failed to generate PQ signature for {test_name}!")
            return None
        
        return {
            "test_name": test_name,
            "description": description,
            "current_actor": current_actor,
            "new_actor": new_actor,
            "old_eth_address": current["eth_address"],
            "new_eth_address": new["eth_address"],
            "pq_fingerprint": current["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_message": base_pq_message.hex(),
            "eth_signature": {
                "v": eth_signature["v"],
                "r": eth_signature["r"],
                "s": eth_signature["s"]
            },
            "pq_signature": pq_signature,
            "eth_nonce": new_eth_nonce,
            "pq_nonce": current_pq_nonce
        }

    def generate_wrong_domain_separator_eth_signature(self, current_actor, new_actor, test_name, description):
        """Generate a change ETH intent vector with wrong domain separator in ETH signature"""
        current = self.actors[current_actor]
        new = self.actors[new_actor]
        
        # Use correct nonces
        current_pq_nonce = 2  # Current actor used nonce 0 for registration, 1 for confirmation
        new_eth_nonce = 0     # New actor first time being used
        
        # Step 1: Create base ETH message
        base_eth_message = self.create_base_eth_message(current["pq_fingerprint"], new["eth_address"], new_eth_nonce)
        
        # Step 2: Sign with WRONG domain separator (this will cause ETH signature to recover to wrong address)
        wrong_domain_separator = "0x" + "00" * 32  # All zeros instead of correct domain separator
        
        # Get the struct hash
        struct_hash = get_change_eth_address_intent_struct_hash(
            new["eth_address"], current["pq_fingerprint"], new_eth_nonce
        )
        
        # Create digest with WRONG domain separator
        wrong_domain_separator_bytes = bytes.fromhex(wrong_domain_separator[2:])
        wrong_digest = keccak(b'\x19\x01' + wrong_domain_separator_bytes + struct_hash)
        
        # Sign the wrong digest
        eth_signature = sign_eip712_message(wrong_digest, new["eth_private_key"])
        
        # Step 3: Create PQ message with correct domain separator
        base_pq_message = self.create_base_pq_message(
            current["eth_address"], new["eth_address"], base_eth_message,
            eth_signature["v"], eth_signature["r"], eth_signature["s"], current_pq_nonce)
        
        # Sign with PQ key
        pq_signature = sign_with_pq_key(base_pq_message, current["pq_private_key_file"])
        
        if pq_signature is None:
            print(f"Failed to generate PQ signature for {test_name}!")
            return None
        
        return {
            "test_name": test_name,
            "description": description,
            "current_actor": current_actor,
            "new_actor": new_actor,
            "old_eth_address": current["eth_address"],
            "new_eth_address": new["eth_address"],
            "pq_fingerprint": current["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_message": base_pq_message.hex(),
            "eth_signature": {
                "v": eth_signature["v"],
                "r": eth_signature["r"],
                "s": eth_signature["s"]
            },
            "pq_signature": pq_signature,
            "eth_nonce": new_eth_nonce,
            "pq_nonce": current_pq_nonce
        }

    def generate_wrong_eth_nonce(self, current_actor, new_actor, test_name, description):
        """Generate a change ETH intent vector with wrong ETH nonce"""
        current = self.actors[current_actor]
        new = self.actors[new_actor]
        
        # Use correct PQ nonce but WRONG ETH nonce
        current_pq_nonce = 2  # Current actor used nonce 0 for registration, 1 for confirmation
        wrong_eth_nonce = 999  # Wrong ETH nonce (should be 0 for first time)
        
        # Step 1: New actor signs the base ETH message with WRONG nonce
        base_eth_message = self.create_base_eth_message(current["pq_fingerprint"], new["eth_address"], wrong_eth_nonce)
        eth_signature = self.sign_eth_message(new["eth_address"], current["pq_fingerprint"], wrong_eth_nonce, new["eth_private_key"])
        
        # Step 2: Current actor's PQ key signs the complete message
        base_pq_message = self.create_base_pq_message(
            current["eth_address"], new["eth_address"], base_eth_message,
            eth_signature["v"], eth_signature["r"], eth_signature["s"], current_pq_nonce)
        pq_signature = sign_with_pq_key(base_pq_message, current["pq_private_key_file"])
        
        if pq_signature is None:
            print(f"Failed to generate PQ signature for {test_name}!")
            return None
        
        return {
            "test_name": test_name,
            "description": description,
            "current_actor": current_actor,
            "new_actor": new_actor,
            "old_eth_address": current["eth_address"],
            "new_eth_address": new["eth_address"],
            "pq_fingerprint": current["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_message": base_pq_message.hex(),
            "eth_signature": {
                "v": eth_signature["v"],
                "r": eth_signature["r"],
                "s": eth_signature["s"]
            },
            "pq_signature": pq_signature,
            "eth_nonce": wrong_eth_nonce,
            "pq_nonce": current_pq_nonce
        }

    def generate_wrong_pq_nonce(self, current_actor, new_actor, test_name, description):
        """Generate a change ETH intent vector with wrong PQ nonce"""
        current = self.actors[current_actor]
        new = self.actors[new_actor]
        
        # Use correct ETH nonce but WRONG PQ nonce
        wrong_pq_nonce = 999  # Wrong PQ nonce (should be 2)
        new_eth_nonce = 0     # New actor first time being used
        
        # Step 1: New actor signs the base ETH message
        base_eth_message = self.create_base_eth_message(current["pq_fingerprint"], new["eth_address"], new_eth_nonce)
        eth_signature = self.sign_eth_message(new["eth_address"], current["pq_fingerprint"], new_eth_nonce, new["eth_private_key"])
        
        # Step 2: Current actor's PQ key signs with WRONG nonce
        base_pq_message = self.create_base_pq_message(
            current["eth_address"], new["eth_address"], base_eth_message,
            eth_signature["v"], eth_signature["r"], eth_signature["s"], wrong_pq_nonce)
        pq_signature = sign_with_pq_key(base_pq_message, current["pq_private_key_file"])
        
        if pq_signature is None:
            print(f"Failed to generate PQ signature for {test_name}!")
            return None
        
        return {
            "test_name": test_name,
            "description": description,
            "current_actor": current_actor,
            "new_actor": new_actor,
            "old_eth_address": current["eth_address"],
            "new_eth_address": new["eth_address"],
            "pq_fingerprint": current["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_message": base_pq_message.hex(),
            "eth_signature": {
                "v": eth_signature["v"],
                "r": eth_signature["r"],
                "s": eth_signature["s"]
            },
            "pq_signature": pq_signature,
            "eth_nonce": new_eth_nonce,
            "pq_nonce": wrong_pq_nonce
        }

    def generate_change_eth_revert_vectors(self) -> Dict[str, Any]:
        """Generate all change ETH revert test vectors"""
        
        print("Starting change ETH revert vector generation...")
        
        alice = self.actors["alice"]
        bob = self.actors["bob"]
        charlie = self.actors["charlie"]
        
        vectors = []
        
        # ============================================================================
        # TEST 1: New ETH Address has pending registration intent
        # ============================================================================
        print("Generating change ETH intent vector 1: AlicePQ → BobETH (BobETH nonce 1 - Bob has pending intent)")
        
        alice_pq_nonce = 2  # AlicePQ used nonce 0 for registration, 1 for confirmation
        bob_eth_nonce = 1   # BobETH used nonce 0 for registration intent, so this is 1
        
        # Step 1: Bob signs the base ETH message
        base_eth_message = self.create_base_eth_message(alice["pq_fingerprint"], bob["eth_address"], bob_eth_nonce)
        eth_signature = self.sign_eth_message(bob["eth_address"], alice["pq_fingerprint"], bob_eth_nonce, bob["eth_private_key"])
        
        # Step 2: Alice's PQ key signs the complete message containing Bob's signature
        base_pq_message = self.create_base_pq_message(
            alice["eth_address"], bob["eth_address"], base_eth_message,
            eth_signature["v"], eth_signature["r"], eth_signature["s"], alice_pq_nonce)
        pq_signature = sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])
        
        if pq_signature is None:
            print("Failed to generate PQ signature for vector 1!")
            return None
        
        vector1 = {
            "test_name": "new_eth_address_has_pending_intent",
            "description": "AlicePQ tries to change ETH to BobETH, but BobETH has pending registration intent",
            "current_actor": "alice",
            "new_actor": "bob", 
            "old_eth_address": alice["eth_address"],
            "new_eth_address": bob["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_message": base_pq_message.hex(),  # For change intent, eth_message is the same as pq_message
            "eth_signature": {
                "v": eth_signature["v"],
                "r": eth_signature["r"],
                "s": eth_signature["s"]
            },
            "pq_signature": pq_signature,
            "eth_nonce": bob_eth_nonce,
            "pq_nonce": alice_pq_nonce
        }
        
        vectors.append(vector1)
        
        # ============================================================================
        # TEST 2: New ETH Address already registered
        # ============================================================================
        print("Generating change ETH intent vector 2: AlicePQ → BobETH (BobETH nonce 2 - Bob is fully registered)")
        
        alice_pq_nonce = 2  # AlicePQ used nonce 0 for registration, 1 for confirmation
        bob_eth_nonce = 2   # BobETH used nonce 0 for registration intent, 1 for confirmation, so this is 2
        
        # Step 1: Bob signs the base ETH message
        base_eth_message = self.create_base_eth_message(alice["pq_fingerprint"], bob["eth_address"], bob_eth_nonce)
        eth_signature = self.sign_eth_message(bob["eth_address"], alice["pq_fingerprint"], bob_eth_nonce, bob["eth_private_key"])
        
        # Step 2: Alice's PQ key signs the complete message containing Bob's signature
        base_pq_message = self.create_base_pq_message(
            alice["eth_address"], bob["eth_address"], base_eth_message,
            eth_signature["v"], eth_signature["r"], eth_signature["s"], alice_pq_nonce)
        pq_signature = sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])
        
        if pq_signature is None:
            print("Failed to generate PQ signature for vector 2!")
            return None
        
        vector2 = {
            "test_name": "new_eth_address_already_registered",
            "description": "AlicePQ tries to change ETH to BobETH, but BobETH is already registered",
            "current_actor": "alice",
            "new_actor": "bob",
            "old_eth_address": alice["eth_address"],
            "new_eth_address": bob["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_message": base_pq_message.hex(),  # For change intent, eth_message is the same as pq_message
            "eth_signature": {
                "v": eth_signature["v"],
                "r": eth_signature["r"],
                "s": eth_signature["s"]
            },
            "pq_signature": pq_signature,
            "eth_nonce": bob_eth_nonce,
            "pq_nonce": alice_pq_nonce
        }
        
        vectors.append(vector2)
        
        # ============================================================================
        # TEST 3: New ETH Address has pending change intent (Charlie conflict)
        # ============================================================================
        
        # Vector 3a: AlicePQ → CharlieETH change intent (CharlieETH nonce 0)
        print("Generating change ETH intent vector 3a: AlicePQ → CharlieETH (CharlieETH nonce 0)")
        
        alice_pq_nonce = 2  # AlicePQ used nonce 0 for registration, 1 for confirmation
        charlie_eth_nonce = 0  # CharlieETH first time being used in change intent
        
        # Step 1: Charlie signs the base ETH message
        base_eth_message = self.create_base_eth_message(alice["pq_fingerprint"], charlie["eth_address"], charlie_eth_nonce)
        eth_signature = self.sign_eth_message(charlie["eth_address"], alice["pq_fingerprint"], charlie_eth_nonce, charlie["eth_private_key"])
        
        # Step 2: Alice's PQ key signs the complete message containing Charlie's signature
        base_pq_message = self.create_base_pq_message(
            alice["eth_address"], charlie["eth_address"], base_eth_message,
            eth_signature["v"], eth_signature["r"], eth_signature["s"], alice_pq_nonce)
        pq_signature = sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])
        
        if pq_signature is None:
            print("Failed to generate PQ signature for vector 3a!")
            return None
        
        vector3a = {
            "test_name": "new_eth_address_has_pending_change_intent_alice",
            "description": "AlicePQ tries to change ETH to CharlieETH, but CharlieETH is already involved in Bob's change intent",
            "current_actor": "alice",
            "new_actor": "charlie", 
            "old_eth_address": alice["eth_address"],
            "new_eth_address": charlie["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_message": base_pq_message.hex(),  # For change intent, eth_message is the same as pq_message
            "eth_signature": {
                "v": eth_signature["v"],
                "r": eth_signature["r"],
                "s": eth_signature["s"]
            },
            "pq_signature": pq_signature,
            "eth_nonce": charlie_eth_nonce,
            "pq_nonce": alice_pq_nonce
        }
        
        vectors.append(vector3a)
        
        # Vector 3b: BobPQ → CharlieETH change intent (CharlieETH nonce 1)
        print("Generating change ETH intent vector 3b: BobPQ → CharlieETH (CharlieETH nonce 1)")
        
        bob_pq_nonce = 2  # BobPQ used nonce 0 for registration, 1 for confirmation
        charlie_eth_nonce = 1  # CharlieETH used nonce 0 in Alice's change intent, so this is 1
        
        # Step 1: Charlie signs the base ETH message
        base_eth_message = self.create_base_eth_message(bob["pq_fingerprint"], charlie["eth_address"], charlie_eth_nonce)
        eth_signature = self.sign_eth_message(charlie["eth_address"], bob["pq_fingerprint"], charlie_eth_nonce, charlie["eth_private_key"])
        
        # Step 2: Bob's PQ key signs the complete message containing Charlie's signature
        base_pq_message = self.create_base_pq_message(
            bob["eth_address"], charlie["eth_address"], base_eth_message,
            eth_signature["v"], eth_signature["r"], eth_signature["s"], bob_pq_nonce)
        pq_signature = sign_with_pq_key(base_pq_message, bob["pq_private_key_file"])
        
        if pq_signature is None:
            print("Failed to generate PQ signature for vector 3b!")
            return None
        
        vector3b = {
            "test_name": "new_eth_address_has_pending_change_intent_bob",
            "description": "BobPQ tries to change ETH to CharlieETH, but CharlieETH is already involved in Alice's change intent",
            "current_actor": "bob",
            "new_actor": "charlie",
            "old_eth_address": bob["eth_address"],
            "new_eth_address": charlie["eth_address"],
            "pq_fingerprint": bob["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_message": base_pq_message.hex(),  # For change intent, eth_message is the same as pq_message
            "eth_signature": {
                "v": eth_signature["v"],
                "r": eth_signature["r"],
                "s": eth_signature["s"]
            },
            "pq_signature": pq_signature,
            "eth_nonce": charlie_eth_nonce,
            "pq_nonce": bob_pq_nonce
        }
        
        vectors.append(vector3b)
        
        # ============================================================================
        # TEST 4: Wrong domain separator in PQ message
        # ============================================================================
        print("Generating change ETH intent vector 4: Wrong domain separator in PQ message")
        wrong_ds_pq_vector = self.generate_wrong_domain_separator_pq_message(
            current_actor="alice",
            new_actor="bob",
            test_name="wrong_domain_separator_pq_message",
            description="AlicePQ tries to change ETH to BobETH with wrong domain separator in PQ message"
        )
        if wrong_ds_pq_vector:
            vectors.append(wrong_ds_pq_vector)
        
        # ============================================================================
        # TEST 5: Wrong domain separator in ETH signature
        # ============================================================================
        print("Generating change ETH intent vector 5: Wrong domain separator in ETH signature")
        wrong_ds_eth_vector = self.generate_wrong_domain_separator_eth_signature(
            current_actor="alice",
            new_actor="bob",
            test_name="wrong_domain_separator_eth_signature",
            description="AlicePQ tries to change ETH to BobETH with wrong domain separator in ETH signature"
        )
        if wrong_ds_eth_vector:
            vectors.append(wrong_ds_eth_vector)
        
        # ============================================================================
        # TEST 6: Wrong ETH nonce
        # ============================================================================
        print("Generating change ETH intent vector 6: Wrong ETH nonce")
        wrong_eth_nonce_vector = self.generate_wrong_eth_nonce(
            current_actor="alice",
            new_actor="bob",
            test_name="wrong_eth_nonce",
            description="AlicePQ tries to change ETH to BobETH with wrong ETH nonce"
        )
        if wrong_eth_nonce_vector:
            vectors.append(wrong_eth_nonce_vector)
        
        # ============================================================================
        # TEST 7: Wrong PQ nonce
        # ============================================================================
        print("Generating change ETH intent vector 7: Wrong PQ nonce")
        wrong_pq_nonce_vector = self.generate_wrong_pq_nonce(
            current_actor="alice",
            new_actor="bob",
            test_name="wrong_pq_nonce",
            description="AlicePQ tries to change ETH to BobETH with wrong PQ nonce"
        )
        if wrong_pq_nonce_vector:
            vectors.append(wrong_pq_nonce_vector)
        
        return {
            "change_eth_address_intent": vectors
        }

def main():
    """Generate change ETH revert test vectors"""
    
    generator = ChangeETHRevertGenerator()
    
    # Create output directory
    output_dir = PROJECT_ROOT / "test" / "test_vectors" / "revert"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate change ETH revert vectors
    change_eth_reverts = generator.generate_change_eth_revert_vectors()
    
    # Write to file
    output_file = output_dir / "change_eth_revert_vectors.json"
    with open(output_file, "w") as f:
        json.dump(change_eth_reverts, f, indent=2)
    
    print(f"Generated change ETH revert vectors: {output_file}")
    print("Change ETH revert test vectors generated successfully!")

if __name__ == "__main__":
    main() 
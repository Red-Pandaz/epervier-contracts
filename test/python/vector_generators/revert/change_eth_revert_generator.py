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
    get_remove_change_intent_struct_hash,
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
        Format: "Intent to change ETH Address and bind with Epervier Fingerprint " + pqFingerprint + " to " + newEthAddress + ethNonce
        This is signed by the new ETH Address (no domain separator in content)
        """
        pattern = b"Intent to change ETH Address and bind with Epervier Fingerprint "
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
        if isinstance(r, str):
            r = int(r, 16)
        if isinstance(s, str):
            s = int(s, 16)
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
        
        # Format signature values as hex strings with 0x prefix (matching working vectors)
        return {
            "v": signature["v"],
            "r": f"0x{signature['r']:064x}",
            "s": f"0x{signature['s']:064x}"
        }

    def sign_remove_change_eth_message(self, pq_fingerprint, eth_nonce, private_key):
        """Sign the remove change ETH address intent message using EIP712"""
        # Get the struct hash for remove change intent
        struct_hash = get_remove_change_intent_struct_hash(
            pq_fingerprint, eth_nonce
        )
        
        # Get the EIP712 digest
        domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
        digest = get_eip712_digest(domain_separator_bytes, struct_hash)
        
        # Sign the digest
        signature = sign_eip712_message(digest, private_key)
        
        # Format signature values as hex strings with 0x prefix (matching working vectors)
        return {
            "v": signature["v"],
            "r": f"0x{signature['r']:064x}",
            "s": f"0x{signature['s']:064x}"
        }

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
        r = eth_signature["r"]
        s = eth_signature["s"]
        if isinstance(r, str):
            r = int(r, 16)
        if isinstance(s, str):
            s = int(s, 16)
        r_bytes = r.to_bytes(32, 'big')
        s_bytes = s.to_bytes(32, 'big')
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
                "r": eth_signature["r"] if isinstance(eth_signature["r"], str) else "0x%064x" % eth_signature["r"],
                "s": eth_signature["s"] if isinstance(eth_signature["s"], str) else "0x%064x" % eth_signature["s"]
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

    def generate_wrong_signer_eth_signature(self, current_actor, new_actor, test_name, description):
        """Generate a change ETH intent vector with ETH signature signed by wrong address"""
        current = self.actors[current_actor]
        new = self.actors[new_actor]
        
        # Use correct nonces
        current_pq_nonce = 2  # Current actor used nonce 0 for registration, 1 for confirmation
        new_eth_nonce = 0     # New actor first time being used
        
        # Step 1: New actor signs the base ETH message
        base_eth_message = self.create_base_eth_message(current["pq_fingerprint"], new["eth_address"], new_eth_nonce)
        
        # Step 2: But sign with Charlie's private key instead of new actor's key (wrong signer)
        charlie = self.actors["charlie"]
        eth_signature = self.sign_eth_message(new["eth_address"], current["pq_fingerprint"], new_eth_nonce, charlie["eth_private_key"])
        
        # Step 3: Current actor's PQ key signs the complete message
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
                "r": eth_signature["r"] if isinstance(eth_signature["r"], str) else "0x%064x" % eth_signature["r"],
                "s": eth_signature["s"] if isinstance(eth_signature["s"], str) else "0x%064x" % eth_signature["s"]
            },
            "pq_signature": pq_signature,
            "eth_nonce": new_eth_nonce,
            "pq_nonce": current_pq_nonce
        }

    def generate_invalid_eth_signature(self, current_actor, new_actor, test_name, description):
        """Generate a change ETH intent vector with invalid ETH signature components"""
        current = self.actors[current_actor]
        new = self.actors[new_actor]
        
        # Use correct nonces
        current_pq_nonce = 2  # Current actor used nonce 0 for registration, 1 for confirmation
        new_eth_nonce = 0     # New actor first time being used
        
        # Step 1: New actor signs the base ETH message
        base_eth_message = self.create_base_eth_message(current["pq_fingerprint"], new["eth_address"], new_eth_nonce)
        
        # Step 2: Use invalid signature components
        eth_signature = {
            "v": 27,  # Invalid v value
            "r": 0x1234567890123456789012345678901234567890123456789012345678901234,
            "s": 0x5678901234567890123456789012345678901234567890123456789012345678
        }
        
        # Step 3: Current actor's PQ key signs the complete message
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
            "eth_nonce": new_eth_nonce,
            "pq_nonce": current_pq_nonce
        }

    def generate_old_eth_address_mismatch(self, current_actor, new_actor, test_name, description):
        """Generate a change ETH intent vector with wrong old ETH address in PQ message"""
        current = self.actors[current_actor]
        new = self.actors[new_actor]
        charlie = self.actors["charlie"]  # Use Charlie's address as wrong old address
        
        # Use correct nonces
        current_pq_nonce = 2  # Current actor used nonce 0 for registration, 1 for confirmation
        new_eth_nonce = 0     # New actor first time being used
        
        # Step 1: New actor signs the base ETH message
        base_eth_message = self.create_base_eth_message(current["pq_fingerprint"], new["eth_address"], new_eth_nonce)
        eth_signature = self.sign_eth_message(new["eth_address"], current["pq_fingerprint"], new_eth_nonce, new["eth_private_key"])
        
        # Step 2: Current actor's PQ key signs with WRONG old ETH address (Charlie's instead of current's)
        base_pq_message = self.create_base_pq_message(
            charlie["eth_address"], new["eth_address"], base_eth_message,  # Wrong old address
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
            "old_eth_address": charlie["eth_address"],  # Wrong old address
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

    def generate_eth_message_pq_fingerprint_mismatch(self, current_actor, new_actor, test_name, description):
        """Generate a change ETH intent vector with wrong PQ fingerprint in ETH message"""
        current = self.actors[current_actor]
        new = self.actors[new_actor]
        charlie = self.actors["charlie"]  # Use Charlie's PQ fingerprint as wrong one
        
        # Use correct nonces
        current_pq_nonce = 2  # Current actor used nonce 0 for registration, 1 for confirmation
        new_eth_nonce = 0     # New actor first time being used
        
        # Step 1: New actor signs the base ETH message with WRONG PQ fingerprint (Charlie's instead of current's)
        base_eth_message = self.create_base_eth_message(charlie["pq_fingerprint"], new["eth_address"], new_eth_nonce)  # Wrong PQ fingerprint
        eth_signature = self.sign_eth_message(new["eth_address"], charlie["pq_fingerprint"], new_eth_nonce, new["eth_private_key"])
        
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
            "eth_nonce": new_eth_nonce,
            "pq_nonce": current_pq_nonce
        }

    def generate_eth_message_new_eth_address_mismatch(self, current_actor, new_actor, test_name, description):
        """Generate a change ETH intent vector with wrong new ETH address in ETH message"""
        current = self.actors[current_actor]
        new = self.actors[new_actor]
        charlie = self.actors["charlie"]  # Use Charlie's address as wrong new address
        
        # Use correct nonces
        current_pq_nonce = 2  # Current actor used nonce 0 for registration, 1 for confirmation
        new_eth_nonce = 0     # New actor first time being used
        
        # Step 1: New actor signs the base ETH message with WRONG new ETH address (Charlie's instead of new's)
        base_eth_message = self.create_base_eth_message(current["pq_fingerprint"], charlie["eth_address"], new_eth_nonce)  # Wrong new address
        eth_signature = self.sign_eth_message(charlie["eth_address"], current["pq_fingerprint"], new_eth_nonce, charlie["eth_private_key"])  # Sign with Charlie's key
        
        # Step 2: Current actor's PQ key signs the complete message
        base_pq_message = self.create_base_pq_message(
            current["eth_address"], new["eth_address"], base_eth_message,  # Correct addresses in PQ message
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
            "eth_nonce": new_eth_nonce,
            "pq_nonce": current_pq_nonce
        }

    def generate_wrong_signer_pq_signature(self, current_actor, new_actor, test_name, description):
        """Generate a change ETH intent vector with PQ signature signed by wrong PQ key"""
        current = self.actors[current_actor]
        new = self.actors[new_actor]
        charlie = self.actors["charlie"]  # Use Charlie's PQ key as wrong signer
        
        # Use correct nonces
        current_pq_nonce = 2  # Current actor used nonce 0 for registration, 1 for confirmation
        new_eth_nonce = 0     # New actor first time being used
        
        # Step 1: New actor signs the base ETH message
        base_eth_message = self.create_base_eth_message(current["pq_fingerprint"], new["eth_address"], new_eth_nonce)
        eth_signature = self.sign_eth_message(new["eth_address"], current["pq_fingerprint"], new_eth_nonce, new["eth_private_key"])
        
        # Step 2: Current actor's PQ key signs the complete message
        base_pq_message = self.create_base_pq_message(
            current["eth_address"], new["eth_address"], base_eth_message,
            eth_signature["v"], eth_signature["r"], eth_signature["s"], current_pq_nonce)
        
        # Step 3: But sign with Charlie's PQ key instead of current actor's key (wrong signer)
        pq_signature = sign_with_pq_key(base_pq_message, charlie["pq_private_key_file"])
        
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

    def generate_invalid_pq_signature(self, current_actor, new_actor, test_name, description):
        """Generate a change ETH intent vector with invalid PQ signature components"""
        current = self.actors[current_actor]
        new = self.actors[new_actor]
        
        # Use correct nonces
        current_pq_nonce = 2  # Current actor used nonce 0 for registration, 1 for confirmation
        new_eth_nonce = 0     # New actor first time being used
        
        # Step 1: New actor signs the base ETH message
        base_eth_message = self.create_base_eth_message(current["pq_fingerprint"], new["eth_address"], new_eth_nonce)
        eth_signature = self.sign_eth_message(new["eth_address"], current["pq_fingerprint"], new_eth_nonce, new["eth_private_key"])
        
        # Step 2: Current actor's PQ key signs the complete message
        base_pq_message = self.create_base_pq_message(
            current["eth_address"], new["eth_address"], base_eth_message,
            eth_signature["v"], eth_signature["r"], eth_signature["s"], current_pq_nonce)
        
        # Step 3: Use invalid PQ signature components
        pq_signature = {
            "salt": "0" * 80,  # Invalid salt (all zeros)
            "cs1": ["0x" + "0" * 64] * 32,  # Invalid cs1 (all zeros)
            "cs2": ["0x" + "0" * 64] * 32,  # Invalid cs2 (all zeros)
            "hint": 0  # Invalid hint
        }
        
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

    def generate_change_eth_revert_vectors(self) -> Dict[str, Any]:
        """Generate all change ETH revert test vectors"""
        
        print("Starting change ETH revert vector generation...")
        
        alice = self.actors["alice"]
        bob = self.actors["bob"]
        charlie = self.actors["charlie"]
        
        vectors = []
        
        # ============================================================================
        # TEST 1: AlicePQ → BobETH change intent (BobETH is unregistered, nonce 0)
        # ============================================================================
        print("Generating change ETH intent vector 1: AlicePQ → BobETH (BobETH nonce 0 - Bob is unregistered)")
        
        alice_pq_nonce = 2  # AlicePQ used nonce 0 for registration, 1 for confirmation
        bob_eth_nonce = 0   # BobETH is unregistered, so his nonce is 0
        
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
                "r": eth_signature["r"] if isinstance(eth_signature["r"], str) else "0x%064x" % eth_signature["r"],
                "s": eth_signature["s"] if isinstance(eth_signature["s"], str) else "0x%064x" % eth_signature["s"]
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
                "r": eth_signature["r"] if isinstance(eth_signature["r"], str) else "0x%064x" % eth_signature["r"],
                "s": eth_signature["s"] if isinstance(eth_signature["s"], str) else "0x%064x" % eth_signature["s"]
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
                "r": eth_signature["r"] if isinstance(eth_signature["r"], str) else "0x%064x" % eth_signature["r"],
                "s": eth_signature["s"] if isinstance(eth_signature["s"], str) else "0x%064x" % eth_signature["s"]
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
                "r": eth_signature["r"] if isinstance(eth_signature["r"], str) else "0x%064x" % eth_signature["r"],
                "s": eth_signature["s"] if isinstance(eth_signature["s"], str) else "0x%064x" % eth_signature["s"]
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
        
        # ============================================================================
        # TEST 8: Wrong signer in ETH signature
        # ============================================================================
        print("Generating change ETH intent vector 8: Wrong signer in ETH signature")
        wrong_signer_vector = self.generate_wrong_signer_eth_signature(
            current_actor="alice",
            new_actor="bob",
            test_name="wrong_signer_eth_signature",
            description="AlicePQ tries to change ETH to BobETH with wrong signer in ETH signature"
        )
        if wrong_signer_vector:
            vectors.append(wrong_signer_vector)
        
        # ============================================================================
        # TEST 9: Invalid ETH signature
        # ============================================================================
        print("Generating change ETH intent vector 9: Invalid ETH signature")
        invalid_signature_vector = self.generate_invalid_eth_signature(
            current_actor="alice",
            new_actor="bob",
            test_name="invalid_eth_signature",
            description="AlicePQ tries to change ETH to BobETH with invalid ETH signature"
        )
        if invalid_signature_vector:
            vectors.append(invalid_signature_vector)
        
        # ============================================================================
        # TEST 10: Old ETH address mismatch in PQ message
        # ============================================================================
        print("Generating change ETH intent vector 10: Old ETH address mismatch in PQ message")
        old_eth_address_mismatch_vector = self.generate_old_eth_address_mismatch(
            current_actor="alice",
            new_actor="bob",
            test_name="old_eth_address_mismatch",
            description="AlicePQ tries to change ETH to BobETH with wrong old ETH address in PQ message"
        )
        if old_eth_address_mismatch_vector:
            vectors.append(old_eth_address_mismatch_vector)
        
        # ============================================================================
        # TEST 11: PQ fingerprint mismatch in ETH message
        # ============================================================================
        print("Generating change ETH intent vector 11: PQ fingerprint mismatch in ETH message")
        pq_fingerprint_mismatch_vector = self.generate_eth_message_pq_fingerprint_mismatch(
            current_actor="alice",
            new_actor="bob",
            test_name="pq_fingerprint_mismatch",
            description="AlicePQ tries to change ETH to BobETH with wrong PQ fingerprint in ETH message"
        )
        if pq_fingerprint_mismatch_vector:
            vectors.append(pq_fingerprint_mismatch_vector)
        
        # ============================================================================
        # TEST 12: New ETH address mismatch in ETH message
        # ============================================================================
        print("Generating change ETH intent vector 12: New ETH address mismatch in ETH message")
        new_eth_address_mismatch_vector = self.generate_eth_message_new_eth_address_mismatch(
            current_actor="alice",
            new_actor="bob",
            test_name="new_eth_address_mismatch",
            description="AlicePQ tries to change ETH to BobETH with wrong new ETH address in ETH message"
        )
        if new_eth_address_mismatch_vector:
            vectors.append(new_eth_address_mismatch_vector)
        
        # ============================================================================
        # TEST 13: Wrong signer in PQ signature
        # ============================================================================
        print("Generating change ETH intent vector 13: Wrong signer in PQ signature")
        wrong_signer_pq_vector = self.generate_wrong_signer_pq_signature(
            current_actor="alice",
            new_actor="bob",
            test_name="wrong_signer_pq_signature",
            description="AlicePQ tries to change ETH to BobETH with wrong signer in PQ signature"
        )
        if wrong_signer_pq_vector:
            vectors.append(wrong_signer_pq_vector)
        
        # ============================================================================
        # TEST 14: Invalid PQ signature
        # ============================================================================
        print("Generating change ETH intent vector 14: Invalid PQ signature")
        invalid_pq_vector = self.generate_invalid_pq_signature(
            current_actor="alice",
            new_actor="bob",
            test_name="invalid_pq_signature",
            description="AlicePQ tries to change ETH to BobETH with invalid PQ signature"
        )
        if invalid_pq_vector:
            vectors.append(invalid_pq_vector)
        
        return {
            "change_eth_address_intent": vectors
        }

    def create_remove_change_eth_eth_message(self, pq_fingerprint, eth_nonce):
        """Create ETH message for removing change ETH address intent by ETH"""
        # Format: "Remove change intent from Epervier Fingerprint " + pqFingerprint + ethNonce
        pattern = b"Remove change intent from Epervier Fingerprint "
        message = (
            pattern +
            bytes.fromhex(pq_fingerprint[2:]) +  # Remove '0x' prefix
            eth_nonce.to_bytes(32, "big")
        )
        assert len(message) == 99, f"ETH removal message must be 99 bytes, got {len(message)}"
        return message

    def create_remove_change_eth_pq_message(self, eth_address, pq_nonce):
        """Create PQ message for removing change ETH address intent by PQ"""
        # Format: DOMAIN_SEPARATOR + "Remove change intent from ETH Address " + ethAddress + pqNonce
        domain_separator = bytes.fromhex("07668882b5c3598c149b213b1c16ab1dd94b45bc4837b468e006b97caef5df92")
        pattern = b"Remove change intent from ETH Address "
        message = (
            domain_separator +
            pattern +
            bytes.fromhex(eth_address[2:]) +  # Remove '0x' prefix
            pq_nonce.to_bytes(32, "big")
        )
        assert len(message) == 122, f"PQ removal message must be 122 bytes, got {len(message)}"
        return message

    def generate_remove_change_eth_revert_vectors(self) -> Dict[str, Any]:
        """Generate all remove change ETH revert test vectors"""
        
        print("Starting remove change ETH revert vector generation...")
        
        alice = self.actors["alice"]
        bob = self.actors["bob"]
        charlie = self.actors["charlie"]
        
        vectors = []
        
        # ============================================================================
        # TEST 1: No pending change intent (ETH removal)
        # ============================================================================
        print("Generating remove change ETH vector 1: No pending change intent (ETH removal)")
        
        # Create a valid ETH removal message but there's no pending intent
        eth_nonce = 1  # Alice used nonce 0 for registration, 1 for confirmation, so next is 1
        eth_message = self.create_remove_change_eth_eth_message(alice["pq_fingerprint"], eth_nonce)
        eth_signature = self.sign_remove_change_eth_message(alice["pq_fingerprint"], eth_nonce, alice["eth_private_key"])
        
        vector1 = {
            "test_name": "no_pending_change_intent_eth",
            "description": "Try to remove change ETH intent by ETH when none exists",
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_address": alice["eth_address"],
            "eth_message": eth_message.hex(),
            "eth_signature": {
                "v": eth_signature["v"],
                "r": eth_signature["r"],
                "s": eth_signature["s"]
            },
            "eth_nonce": eth_nonce
        }
        
        vectors.append(vector1)
        
        # ============================================================================
        # TEST 2: Wrong domain separator (ETH removal)
        # ============================================================================
        print("Generating remove change ETH vector 2: Wrong domain separator (ETH removal)")
        
        # Create ETH removal message with wrong domain separator
        # ETH removal message format: pattern (47 bytes) + pq_fingerprint (20 bytes) + eth_nonce (32 bytes) = 99 bytes
        # Sign it with wrong domain separator so signature recovery fails
        pattern = b"Remove change intent from Epervier Fingerprint "  # 47 bytes
        pq_fingerprint_bytes = bytes.fromhex(alice['pq_fingerprint'][2:])  # 20 bytes
        eth_nonce_bytes = eth_nonce.to_bytes(32, 'big')  # 32 bytes
        wrong_eth_message = pattern + pq_fingerprint_bytes + eth_nonce_bytes  # 99 bytes total
        
        # Sign with wrong domain separator so signature recovery fails
        wrong_domain_separator = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        struct_hash = get_remove_change_intent_struct_hash(alice["pq_fingerprint"], eth_nonce)
        wrong_domain_separator_bytes = bytes.fromhex(wrong_domain_separator[2:])
        wrong_digest = get_eip712_digest(wrong_domain_separator_bytes, struct_hash)
        wrong_eth_signature = sign_eip712_message(wrong_digest, alice["eth_private_key"])
        
        vector2 = {
            "test_name": "wrong_domain_separator_eth_removal",
            "description": "Try to remove change ETH intent by ETH with wrong domain separator",
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_address": alice["eth_address"],
            "eth_message": wrong_eth_message.hex(),
            "eth_signature": {
                "v": wrong_eth_signature["v"],
                "r": wrong_eth_signature["r"],
                "s": wrong_eth_signature["s"]
            },
            "eth_nonce": eth_nonce
        }
        
        vectors.append(vector2)
        
        # ============================================================================
        # TEST 3: Wrong ETH nonce (ETH removal)
        # ============================================================================
        print("Generating remove change ETH vector 3: Wrong ETH nonce (ETH removal)")
        
        # Create ETH removal message with wrong nonce
        # The change intent is: Alice's PQ fingerprint -> Bob's ETH address
        # So Bob should sign to remove the change intent
        wrong_eth_nonce = 999
        eth_message_wrong_nonce = self.create_remove_change_eth_eth_message(alice["pq_fingerprint"], wrong_eth_nonce)
        eth_signature_wrong_nonce = self.sign_remove_change_eth_message(alice["pq_fingerprint"], wrong_eth_nonce, bob["eth_private_key"])
        
        vector3 = {
            "test_name": "wrong_eth_nonce_eth_removal",
            "description": "Try to remove change ETH intent by ETH with wrong ETH nonce",
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_address": bob["eth_address"],  # Bob's address because he's the new ETH address in the change intent
            "eth_message": eth_message_wrong_nonce.hex(),
            "eth_signature": {
                "v": eth_signature_wrong_nonce["v"],
                "r": eth_signature_wrong_nonce["r"],
                "s": eth_signature_wrong_nonce["s"]
            },
            "eth_nonce": wrong_eth_nonce
        }
        
        vectors.append(vector3)
        
        # ============================================================================
        # TEST 4: Wrong signer (ETH removal)
        # ============================================================================
        print("Generating remove change ETH vector 4: Wrong signer (ETH removal)")
        
        # Create ETH removal message signed by wrong ETH key
        # The change intent is: Alice's PQ fingerprint -> Bob's ETH address
        # So Bob should sign, but we'll use Charlie's key instead
        eth_message_wrong_signer = self.create_remove_change_eth_eth_message(alice["pq_fingerprint"], eth_nonce)
        eth_signature_wrong_signer = self.sign_remove_change_eth_message(alice["pq_fingerprint"], eth_nonce, charlie["eth_private_key"])
        
        vector4 = {
            "test_name": "wrong_signer_eth_removal",
            "description": "Try to remove change ETH intent by ETH with wrong signer",
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_address": bob["eth_address"],  # Bob's address because he's the new ETH address in the change intent
            "eth_message": eth_message_wrong_signer.hex(),
            "eth_signature": {
                "v": eth_signature_wrong_signer["v"],
                "r": eth_signature_wrong_signer["r"],
                "s": eth_signature_wrong_signer["s"]
            },
            "eth_nonce": eth_nonce
        }
        
        vectors.append(vector4)
        
        # ============================================================================
        # TEST 5: No pending change intent (PQ removal)
        # ============================================================================
        print("Generating remove change ETH vector 5: No pending change intent (PQ removal)")
        
        # Create a valid PQ removal message but there's no pending intent
        # The change intent is: Alice's PQ fingerprint -> Bob's ETH address
        # So Alice's PQ key should sign to remove the change intent for Bob's ETH address
        pq_nonce = 0
        pq_message = self.create_remove_change_eth_pq_message(bob["eth_address"], pq_nonce)
        pq_signature = sign_with_pq_key(pq_message, alice["pq_private_key_file"])
        
        if pq_signature is None:
            print("Failed to generate PQ signature for vector 5!")
            return None
        
        vector5 = {
            "test_name": "no_pending_change_intent_pq",
            "description": "Try to remove change ETH intent by PQ when none exists",
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_address": bob["eth_address"],  # Bob's address because he's the new ETH address in the change intent
            "pq_message": pq_message.hex(),
            "pq_signature": pq_signature,
            "pq_nonce": pq_nonce
        }
        
        vectors.append(vector5)
        
        # ============================================================================
        # TEST 6: Wrong domain separator (PQ removal)
        # ============================================================================
        print("Generating remove change ETH vector 6: Wrong domain separator (PQ removal)")
        # The change intent is: Alice's PQ fingerprint -> Bob's ETH address
        # Use correct pattern, address, and nonce, but wrong domain separator
        wrong_domain_separator = bytes.fromhex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        # Use exact pattern from schema: "Remove change intent from ETH Address " (38 bytes)
        pattern = b"Remove change intent from ETH Address "
        eth_addr_bytes = bytes.fromhex(bob['eth_address'][2:])  # 20 bytes
        pq_nonce_bytes = pq_nonce.to_bytes(32, "big")  # 32 bytes
        # Build the message exactly according to schema: DOMAIN_SEPARATOR + pattern + ethAddress + pqNonce
        wrong_pq_message = wrong_domain_separator + pattern + eth_addr_bytes + pq_nonce_bytes
        # Verify exact length: 32 + 38 + 20 + 32 = 122 bytes
        assert len(wrong_pq_message) == 122, f"PQ removal message must be 122 bytes, got {len(wrong_pq_message)}"
        assert len(pattern) == 38, f"Pattern must be 38 bytes, got {len(pattern)}"
        # Sign with Alice's PQ key
        wrong_pq_signature = sign_with_pq_key(wrong_pq_message, alice["pq_private_key_file"])
        if wrong_pq_signature is None:
            print("Failed to generate PQ signature for vector 6!")
            return None
        vector6 = {
            "test_name": "wrong_domain_separator_pq_removal",
            "description": "Try to remove change ETH intent by PQ with wrong domain separator",
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_address": bob["eth_address"],
            "pq_message": wrong_pq_message.hex(),
            "pq_signature": wrong_pq_signature,
            "pq_nonce": pq_nonce
        }
        vectors.append(vector6)
        
        # ============================================================================
        # TEST 7: Wrong PQ nonce (PQ removal)
        # ============================================================================
        print("Generating remove change ETH vector 7: Wrong PQ nonce (PQ removal)")
        
        # Create PQ removal message with wrong nonce
        # The change intent is: Alice's PQ fingerprint -> Bob's ETH address
        wrong_pq_nonce = 999
        pq_message_wrong_nonce = self.create_remove_change_eth_pq_message(bob["eth_address"], wrong_pq_nonce)
        pq_signature_wrong_nonce = sign_with_pq_key(pq_message_wrong_nonce, alice["pq_private_key_file"])
        
        if pq_signature_wrong_nonce is None:
            print("Failed to generate PQ signature for vector 7!")
            return None
        
        vector7 = {
            "test_name": "wrong_pq_nonce_pq_removal",
            "description": "Try to remove change ETH intent by PQ with wrong PQ nonce",
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_address": bob["eth_address"],  # Bob's address because he's the new ETH address in the change intent
            "pq_message": pq_message_wrong_nonce.hex(),
            "pq_signature": pq_signature_wrong_nonce,
            "pq_nonce": wrong_pq_nonce
        }
        
        vectors.append(vector7)
        
        # ============================================================================
        # TEST 8: Wrong signer (PQ removal)
        # ============================================================================
        print("Generating remove change ETH vector 8: Wrong signer (PQ removal)")
        
        # Create PQ removal message signed by wrong PQ key
        # The change intent is: Alice's PQ fingerprint -> Bob's ETH address
        # So Alice's PQ key should sign, but we'll use Bob's PQ key instead
        pq_message_wrong_signer = self.create_remove_change_eth_pq_message(bob["eth_address"], pq_nonce)
        pq_signature_wrong_signer = sign_with_pq_key(pq_message_wrong_signer, bob["pq_private_key_file"])
        
        if pq_signature_wrong_signer is None:
            print("Failed to generate PQ signature for vector 8!")
            return None
        
        vector8 = {
            "test_name": "wrong_signer_pq_removal",
            "description": "Try to remove change ETH intent by PQ with wrong signer",
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_address": bob["eth_address"],  # Bob's address because he's the new ETH address in the change intent
            "pq_message": pq_message_wrong_signer.hex(),
            "pq_signature": pq_signature_wrong_signer,
            "pq_nonce": pq_nonce
        }
        
        vectors.append(vector8)
        
        # ============================================================================
        # TEST 9: Invalid PQ signature (PQ removal)
        # ============================================================================
        print("Generating remove change ETH vector 9: Invalid PQ signature (PQ removal)")
        
        # Create PQ removal message with invalid signature components
        # The change intent is: Alice's PQ fingerprint -> Bob's ETH address
        pq_message_invalid = self.create_remove_change_eth_pq_message(bob["eth_address"], pq_nonce)
        
        vector9 = {
            "test_name": "invalid_pq_signature_pq_removal",
            "description": "Try to remove change ETH intent by PQ with invalid PQ signature",
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_address": bob["eth_address"],  # Bob's address because he's the new ETH address in the change intent
            "pq_message": pq_message_invalid.hex(),
            "pq_nonce": pq_nonce
        }
        
        vectors.append(vector9)
        
        # ============================================================================
        # TEST 10: Wrong address in message (ETH removal) - Alice's ETH key tries to cancel Alice's intent
        # ============================================================================
        print("Generating remove change ETH vector 10: Wrong address in message (ETH removal) - Alice's ETH key")
        
        # Scenario: Alice has a change intent (Alice's PQ fingerprint -> Bob's ETH address)
        # Alice's ETH key tries to cancel Alice's intent (simulating compromised ETH keys)
        # Alice's ETH key should NOT be able to cancel Alice's PQ-controlled change intent
        # The message contains Alice's PQ fingerprint but is signed by Alice's ETH key
        eth_message_alice_eth = self.create_remove_change_eth_eth_message(alice["pq_fingerprint"], eth_nonce)
        eth_signature_alice_eth = self.sign_remove_change_eth_message(alice["pq_fingerprint"], eth_nonce, alice["eth_private_key"])
        
        vector10 = {
            "test_name": "wrong_address_in_message_eth_removal_alice_eth",
            "description": "Alice's ETH key tries to cancel Alice's change intent (simulating compromised keys)",
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_address": alice["eth_address"],  # Alice's address (the signer)
            "eth_message": eth_message_alice_eth.hex(),
            "eth_signature": {
                "v": eth_signature_alice_eth["v"],
                "r": eth_signature_alice_eth["r"],
                "s": eth_signature_alice_eth["s"]
            },
            "eth_nonce": eth_nonce
        }
        
        vectors.append(vector10)
        
        # ============================================================================
        # TEST 10b: Wrong address in message (ETH removal) - Charlie's ETH key tries to cancel Alice's intent
        # ============================================================================
        print("Generating remove change ETH vector 10b: Wrong address in message (ETH removal) - Charlie's ETH key")
        
        # Scenario: Alice has a change intent (Alice's PQ fingerprint -> Bob's ETH address)
        # Charlie's ETH key tries to cancel Alice's intent (unauthorized third party)
        # Charlie's ETH key should NOT be able to cancel Alice's change intent
        # The message contains Alice's PQ fingerprint but is signed by Charlie's ETH key
        eth_message_charlie_eth = self.create_remove_change_eth_eth_message(alice["pq_fingerprint"], eth_nonce)
        eth_signature_charlie_eth = self.sign_remove_change_eth_message(alice["pq_fingerprint"], eth_nonce, charlie["eth_private_key"])
        
        vector10b = {
            "test_name": "wrong_address_in_message_eth_removal_charlie_eth",
            "description": "Charlie's ETH key tries to cancel Alice's change intent (unauthorized third party)",
            "pq_fingerprint": alice["pq_fingerprint"],
            "eth_address": charlie["eth_address"],  # Charlie's address (the signer)
            "eth_message": eth_message_charlie_eth.hex(),
            "eth_signature": {
                "v": eth_signature_charlie_eth["v"],
                "r": eth_signature_charlie_eth["r"],
                "s": eth_signature_charlie_eth["s"]
            },
            "eth_nonce": eth_nonce
        }
        
        vectors.append(vector10b)
        
        # ============================================================================
        # TEST 11: Wrong fingerprint in message (PQ removal) - Charlie's PQ key tries to cancel Alice's intent
        # ============================================================================
        print("Generating remove change ETH vector 11: Wrong fingerprint in message (PQ removal)")
        
        # Scenario: Alice has a change intent (Alice's PQ fingerprint -> Bob's ETH address)
        # Charlie tries to cancel Alice's intent by creating a message that says "cancel Alice's intent"
        # but is signed by Charlie's PQ key (who is not authorized to cancel Alice's intent)
        # The message contains Bob's ETH address but is signed by Charlie's PQ key instead of Alice's
        pq_message_wrong_fingerprint = self.create_remove_change_eth_pq_message(bob["eth_address"], pq_nonce)
        pq_signature_wrong_fingerprint = sign_with_pq_key(pq_message_wrong_fingerprint, charlie["pq_private_key_file"])
        
        if pq_signature_wrong_fingerprint is None:
            print("Failed to generate PQ signature for vector 11!")
            return None
        
        vector11 = {
            "test_name": "wrong_fingerprint_in_message_pq_removal",
            "description": "Charlie's PQ key tries to cancel Alice's change intent (unauthorized third party)",
            "pq_fingerprint": charlie["pq_fingerprint"],  # Charlie's fingerprint (the signer)
            "eth_address": bob["eth_address"],  # Bob's address in the message
            "pq_message": pq_message_wrong_fingerprint.hex(),
            "pq_signature": pq_signature_wrong_fingerprint,
            "pq_nonce": pq_nonce
        }
        
        vectors.append(vector11)
        
        return {
            "remove_change_eth_address_intent": vectors
        }

    def generate_confirm_change_eth_revert_vectors(self) -> Dict[str, Any]:
        """Generate revert test vectors for confirm change ETH address"""
        print("Generating confirm change ETH address revert vectors...")
        vectors = []
        alice = self.actors["alice"]
        bob = self.actors["bob"]
        charlie = self.actors["charlie"]

        # Create a valid base setup for all tests
        eth_nonce = 1
        pq_nonce = 3
        base_pq_message = self.create_base_pq_confirm_message(alice["eth_address"], bob["eth_address"], pq_nonce)
        pq_signature = sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])
        if pq_signature is None:
            print("Failed to generate PQ signature for valid setup!")
            return {}
        
        eth_message = self.create_eth_confirm_message(alice["pq_fingerprint"], base_pq_message, bytes.fromhex(pq_signature["salt"]), [int(x, 16) for x in pq_signature["cs1"]], [int(x, 16) for x in pq_signature["cs2"]], pq_signature["hint"], eth_nonce)
        eth_signature = self.sign_eth_confirm_message(eth_message, bob["eth_private_key"], alice["eth_address"], alice["pq_fingerprint"], base_pq_message, bytes.fromhex(pq_signature["salt"]), [int(x, 16) for x in pq_signature["cs1"]], [int(x, 16) for x in pq_signature["cs2"]], pq_signature["hint"], eth_nonce)

        # 1. Malformed message - wrong pattern at the start, correct length
        wrong_pattern = b"THIS IS NOT THE RIGHT PATTERN FOR CONFIRM CHANGE ETH ADDRESS!"
        malformed_eth_message = wrong_pattern + b"\x00" * (len(eth_message) - len(wrong_pattern))
        assert len(malformed_eth_message) == len(eth_message), f"Malformed message must be {len(eth_message)} bytes, got {len(malformed_eth_message)}"
        vectors.append({
            "test_name": "malformed_message",
            "description": "Test revert when ETH message has wrong pattern at the start (correct length)",
            "current_actor": "alice",
            "new_actor": "bob",
            "eth_message": malformed_eth_message.hex(),
            "eth_signature": eth_signature,
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce,
            "expected_revert": "Invalid ETH change address confirmation message"
        })

        # 2. Invalid ETH signature - corrupted r value
        invalid_eth_signature = {
            "v": eth_signature["v"],
            "r": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "s": eth_signature["s"]
        }
        vectors.append({
            "test_name": "invalid_eth_signature",
            "description": "Test revert when ETH signature is cryptographically invalid",
            "current_actor": "alice",
            "new_actor": "bob",
            "eth_message": eth_message.hex(),
            "eth_signature": invalid_eth_signature,
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce,
            "expected_revert": "Invalid ETH signature"
        })

        # 3. Invalid PQ signature - corrupted cs1 values
        invalid_pq_signature = pq_signature.copy()
        invalid_pq_signature["cs1"] = ["0x0000000000000000000000000000000000000000000000000000000000000000"] * 32
        eth_message_invalid_pq = self.create_eth_confirm_message(alice["pq_fingerprint"], base_pq_message, bytes.fromhex(invalid_pq_signature["salt"]), [int(x, 16) for x in invalid_pq_signature["cs1"]], [int(x, 16) for x in invalid_pq_signature["cs2"]], invalid_pq_signature["hint"], eth_nonce)
        eth_signature_invalid_pq = self.sign_eth_confirm_message(eth_message_invalid_pq, bob["eth_private_key"], alice["eth_address"], alice["pq_fingerprint"], base_pq_message, bytes.fromhex(invalid_pq_signature["salt"]), [int(x, 16) for x in invalid_pq_signature["cs1"]], [int(x, 16) for x in invalid_pq_signature["cs2"]], invalid_pq_signature["hint"], eth_nonce)
        vectors.append({
            "test_name": "invalid_pq_signature",
            "description": "Test revert when PQ signature is cryptographically invalid",
            "current_actor": "alice",
            "new_actor": "bob",
            "eth_message": eth_message_invalid_pq.hex(),
            "eth_signature": eth_signature_invalid_pq,
            "pq_signature": invalid_pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce,
            "expected_revert": "Invalid PQ signature"
        })

        # 4. ETH address mismatch - PQ message has different ETH address than signature
        # Create a valid ETH signature that recovers to Bob's address
        # But put Charlie's address in the PQ message as the old ETH address
        # This should trigger "ETH Address mismatch: PQ message vs recovered ETH signature"
        base_pq_message_eth_mismatch = self.create_base_pq_confirm_message(charlie["eth_address"], bob["eth_address"], pq_nonce)  # Use Charlie's address as old address
        pq_signature_eth_mismatch = sign_with_pq_key(base_pq_message_eth_mismatch, alice["pq_private_key_file"])
        if pq_signature_eth_mismatch is not None:
            eth_message_eth_mismatch = self.create_eth_confirm_message(alice["pq_fingerprint"], base_pq_message_eth_mismatch, bytes.fromhex(pq_signature_eth_mismatch["salt"]), [int(x, 16) for x in pq_signature_eth_mismatch["cs1"]], [int(x, 16) for x in pq_signature_eth_mismatch["cs2"]], pq_signature_eth_mismatch["hint"], eth_nonce)
            # Sign with Bob's key (so signature recovers to Bob's address)
            # But PQ message contains Charlie's address as old address
            eth_signature_eth_mismatch = self.sign_eth_confirm_message(eth_message_eth_mismatch, bob["eth_private_key"], charlie["eth_address"], alice["pq_fingerprint"], base_pq_message_eth_mismatch, bytes.fromhex(pq_signature_eth_mismatch["salt"]), [int(x, 16) for x in pq_signature_eth_mismatch["cs1"]], [int(x, 16) for x in pq_signature_eth_mismatch["cs2"]], pq_signature_eth_mismatch["hint"], eth_nonce)
            vectors.append({
                "test_name": "eth_address_mismatch",
                "description": "Test revert when ETH address in PQ message doesn't match recovered ETH signature",
                "current_actor": "alice",
                "new_actor": "bob",
                "eth_message": eth_message_eth_mismatch.hex(),
                "eth_signature": eth_signature_eth_mismatch,
                "pq_signature": pq_signature_eth_mismatch,
                "eth_nonce": eth_nonce,
                "pq_nonce": pq_nonce,
                "expected_revert": "ETH Address mismatch: PQ message vs recovered ETH signature"
            })

        # 5. PQ fingerprint mismatch - ETH message has different PQ fingerprint than signature
        base_pq_message_pq_mismatch = self.create_base_pq_confirm_message(alice["eth_address"], bob["eth_address"], pq_nonce)
        pq_signature_pq_mismatch = sign_with_pq_key(base_pq_message_pq_mismatch, bob["pq_private_key_file"])  # Use Bob's PQ key instead of Alice's
        if pq_signature_pq_mismatch is not None:
            eth_message_pq_mismatch = self.create_eth_confirm_message(alice["pq_fingerprint"], base_pq_message_pq_mismatch, bytes.fromhex(pq_signature_pq_mismatch["salt"]), [int(x, 16) for x in pq_signature_pq_mismatch["cs1"]], [int(x, 16) for x in pq_signature_pq_mismatch["cs2"]], pq_signature_pq_mismatch["hint"], eth_nonce)
            eth_signature_pq_mismatch = self.sign_eth_confirm_message(eth_message_pq_mismatch, bob["eth_private_key"], alice["eth_address"], alice["pq_fingerprint"], base_pq_message_pq_mismatch, bytes.fromhex(pq_signature_pq_mismatch["salt"]), [int(x, 16) for x in pq_signature_pq_mismatch["cs1"]], [int(x, 16) for x in pq_signature_pq_mismatch["cs2"]], pq_signature_pq_mismatch["hint"], eth_nonce)
            vectors.append({
                "test_name": "pq_fingerprint_mismatch",
                "description": "Test revert when PQ fingerprint in ETH message doesn't match recovered PQ signature",
                "current_actor": "alice",
                "new_actor": "bob",
                "eth_message": eth_message_pq_mismatch.hex(),
                "eth_signature": eth_signature_pq_mismatch,
                "pq_signature": pq_signature_pq_mismatch,
                "eth_nonce": eth_nonce,
                "pq_nonce": pq_nonce,
                "expected_revert": "PQ fingerprint mismatch: ETH message vs recovered PQ signature"
            })

        # 6. Intent ETH address mismatch - PQ message has different intent ETH address
        base_pq_message_intent_mismatch = self.create_base_pq_confirm_message(charlie["eth_address"], bob["eth_address"], pq_nonce)  # Use Charlie's address as old address
        pq_signature_intent_mismatch = sign_with_pq_key(base_pq_message_intent_mismatch, alice["pq_private_key_file"])
        if pq_signature_intent_mismatch is not None:
            eth_message_intent_mismatch = self.create_eth_confirm_message(alice["pq_fingerprint"], base_pq_message_intent_mismatch, bytes.fromhex(pq_signature_intent_mismatch["salt"]), [int(x, 16) for x in pq_signature_intent_mismatch["cs1"]], [int(x, 16) for x in pq_signature_intent_mismatch["cs2"]], pq_signature_intent_mismatch["hint"], eth_nonce)
            eth_signature_intent_mismatch = self.sign_eth_confirm_message(eth_message_intent_mismatch, bob["eth_private_key"], alice["eth_address"], alice["pq_fingerprint"], base_pq_message_intent_mismatch, bytes.fromhex(pq_signature_intent_mismatch["salt"]), [int(x, 16) for x in pq_signature_intent_mismatch["cs1"]], [int(x, 16) for x in pq_signature_intent_mismatch["cs2"]], pq_signature_intent_mismatch["hint"], eth_nonce)
            vectors.append({
                "test_name": "intent_eth_address_mismatch",
                "description": "Test revert when intent ETH address in PQ message doesn't match expected",
                "current_actor": "alice",
                "new_actor": "bob",
                "eth_message": eth_message_intent_mismatch.hex(),
                "eth_signature": eth_signature_intent_mismatch,
                "pq_signature": pq_signature_intent_mismatch,
                "eth_nonce": eth_nonce,
                "pq_nonce": pq_nonce,
                "expected_revert": "Intent ETH address mismatch"
            })

        # 7. Wrong ETH nonce
        wrong_eth_nonce = 999
        eth_message_wrong_eth_nonce = self.create_eth_confirm_message(alice["pq_fingerprint"], base_pq_message, bytes.fromhex(pq_signature["salt"]), [int(x, 16) for x in pq_signature["cs1"]], [int(x, 16) for x in pq_signature["cs2"]], pq_signature["hint"], wrong_eth_nonce)
        eth_signature_wrong_eth_nonce = self.sign_eth_confirm_message(eth_message_wrong_eth_nonce, bob["eth_private_key"], alice["eth_address"], alice["pq_fingerprint"], base_pq_message, bytes.fromhex(pq_signature["salt"]), [int(x, 16) for x in pq_signature["cs1"]], [int(x, 16) for x in pq_signature["cs2"]], pq_signature["hint"], wrong_eth_nonce)
        vectors.append({
            "test_name": "wrong_eth_nonce",
            "description": "Test revert when ETH nonce is wrong",
            "current_actor": "alice",
            "new_actor": "bob",
            "eth_message": eth_message_wrong_eth_nonce.hex(),
            "eth_signature": eth_signature_wrong_eth_nonce,
            "pq_signature": pq_signature,
            "eth_nonce": wrong_eth_nonce,
            "pq_nonce": pq_nonce,
            "expected_revert": "Invalid ETH nonce"
        })

        # 8. Wrong PQ nonce
        wrong_pq_nonce = 999
        base_pq_message_wrong_pq_nonce = self.create_base_pq_confirm_message(alice["eth_address"], bob["eth_address"], wrong_pq_nonce)
        pq_signature_wrong_pq_nonce = sign_with_pq_key(base_pq_message_wrong_pq_nonce, alice["pq_private_key_file"])
        if pq_signature_wrong_pq_nonce is not None:
            eth_message_wrong_pq_nonce = self.create_eth_confirm_message(alice["pq_fingerprint"], base_pq_message_wrong_pq_nonce, bytes.fromhex(pq_signature_wrong_pq_nonce["salt"]), [int(x, 16) for x in pq_signature_wrong_pq_nonce["cs1"]], [int(x, 16) for x in pq_signature_wrong_pq_nonce["cs2"]], pq_signature_wrong_pq_nonce["hint"], eth_nonce)
            eth_signature_wrong_pq_nonce = self.sign_eth_confirm_message(eth_message_wrong_pq_nonce, bob["eth_private_key"], alice["eth_address"], alice["pq_fingerprint"], base_pq_message_wrong_pq_nonce, bytes.fromhex(pq_signature_wrong_pq_nonce["salt"]), [int(x, 16) for x in pq_signature_wrong_pq_nonce["cs1"]], [int(x, 16) for x in pq_signature_wrong_pq_nonce["cs2"]], pq_signature_wrong_pq_nonce["hint"], eth_nonce)
            vectors.append({
                "test_name": "wrong_pq_nonce",
                "description": "Test revert when PQ nonce is wrong",
                "current_actor": "alice",
                "new_actor": "bob",
                "eth_message": eth_message_wrong_pq_nonce.hex(),
                "eth_signature": eth_signature_wrong_pq_nonce,
                "pq_signature": pq_signature_wrong_pq_nonce,
                "eth_nonce": eth_nonce,
                "pq_nonce": wrong_pq_nonce,
                "expected_revert": "Invalid PQ nonce"
            })

        # 9. Wrong ETH signer - signature from Charlie instead of Bob
        eth_signature_wrong_signer = self.sign_eth_confirm_message(eth_message, charlie["eth_private_key"], alice["eth_address"], alice["pq_fingerprint"], base_pq_message, bytes.fromhex(pq_signature["salt"]), [int(x, 16) for x in pq_signature["cs1"]], [int(x, 16) for x in pq_signature["cs2"]], pq_signature["hint"], eth_nonce)
        vectors.append({
            "test_name": "wrong_eth_signer",
            "description": "Test revert when ETH signature is from wrong key",
            "current_actor": "alice",
            "new_actor": "bob",
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature_wrong_signer,
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce,
            "expected_revert": "ETH Address mismatch: PQ message vs recovered ETH signature"
        })

        # 10. Wrong PQ signer - signature from Bob instead of Alice
        pq_signature_wrong_pq_signer = sign_with_pq_key(base_pq_message, bob["pq_private_key_file"])
        if pq_signature_wrong_pq_signer is not None:
            eth_message_wrong_pq_signer = self.create_eth_confirm_message(alice["pq_fingerprint"], base_pq_message, bytes.fromhex(pq_signature_wrong_pq_signer["salt"]), [int(x, 16) for x in pq_signature_wrong_pq_signer["cs1"]], [int(x, 16) for x in pq_signature_wrong_pq_signer["cs2"]], pq_signature_wrong_pq_signer["hint"], eth_nonce)
            eth_signature_wrong_pq_signer = self.sign_eth_confirm_message(eth_message_wrong_pq_signer, bob["eth_private_key"], alice["eth_address"], alice["pq_fingerprint"], base_pq_message, bytes.fromhex(pq_signature_wrong_pq_signer["salt"]), [int(x, 16) for x in pq_signature_wrong_pq_signer["cs1"]], [int(x, 16) for x in pq_signature_wrong_pq_signer["cs2"]], pq_signature_wrong_pq_signer["hint"], eth_nonce)
            vectors.append({
                "test_name": "wrong_pq_signer",
                "description": "Test revert when PQ signature is from wrong key",
                "current_actor": "alice",
                "new_actor": "bob",
                "eth_message": eth_message_wrong_pq_signer.hex(),
                "eth_signature": eth_signature_wrong_pq_signer,
                "pq_signature": pq_signature_wrong_pq_signer,
                "eth_nonce": eth_nonce,
                "pq_nonce": pq_nonce,
                "expected_revert": "PQ fingerprint mismatch: ETH message vs recovered PQ signature"
            })

        # 11. Wrong domain separator
        eth_signature_wrong_domain = self.sign_eth_confirm_message_with_wrong_domain(eth_message, bob["eth_private_key"], alice["eth_address"], alice["pq_fingerprint"], base_pq_message, bytes.fromhex(pq_signature["salt"]), [int(x, 16) for x in pq_signature["cs1"]], [int(x, 16) for x in pq_signature["cs2"]], pq_signature["hint"], eth_nonce)
        vectors.append({
            "test_name": "wrong_domain_separator",
            "description": "Test revert when ETH signature uses wrong domain separator",
            "current_actor": "alice",
            "new_actor": "bob",
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature_wrong_domain,
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce,
            "expected_revert": "Invalid ETH signature"
        })

        # 12. No pending intent (this will be tested by not setting up the intent in the test)
        vectors.append({
            "test_name": "no_pending_intent",
            "description": "Test revert when there's no pending change intent",
            "current_actor": "alice",
            "new_actor": "bob",
            "eth_message": eth_message.hex(),
            "eth_signature": eth_signature,
            "pq_signature": pq_signature,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce,
            "expected_revert": "No pending change intent found for PQ fingerprint"
        })

        return {
            "confirm_change_eth_address": vectors
        }

    def create_base_pq_confirm_message(self, old_eth_address, new_eth_address, pq_nonce):
        """Create base PQ message for change ETH Address confirmation"""
        domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])
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

    def create_eth_confirm_message(self, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
        """Create ETH message for change ETH Address confirmation"""
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

    def sign_eth_confirm_message(self, message_bytes, private_key, old_eth_address, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
        """Sign ETH confirmation message using EIP712"""
        from eip712_helpers import get_change_eth_address_confirmation_struct_hash, get_eip712_digest, sign_eip712_message
        
        domain_separator = bytes.fromhex(DOMAIN_SEPARATOR[2:])
        struct_hash = get_change_eth_address_confirmation_struct_hash(old_eth_address, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce)
        digest = get_eip712_digest(domain_separator, struct_hash)
        signature = sign_eip712_message(digest, private_key)
        
        # Format signature values as hex strings with 0x prefix (matching working vectors)
        return {
            "v": signature["v"],
            "r": f"0x{signature['r']:064x}",
            "s": f"0x{signature['s']:064x}"
        }

    def sign_eth_confirm_message_with_wrong_domain(self, message_bytes, private_key, old_eth_address, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
        """Sign ETH confirmation message using EIP712 with wrong domain separator"""
        from eip712_helpers import get_change_eth_address_confirmation_struct_hash, get_eip712_digest, sign_eip712_message
        
        # Use wrong domain separator
        wrong_domain_separator = bytes.fromhex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        struct_hash = get_change_eth_address_confirmation_struct_hash(old_eth_address, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce)
        digest = get_eip712_digest(wrong_domain_separator, struct_hash)
        signature = sign_eip712_message(digest, private_key)
        
        # Format signature values as hex strings with 0x prefix (matching working vectors)
        return {
            "v": signature["v"],
            "r": f"0x{signature['r']:064x}",
            "s": f"0x{signature['s']:064x}"
        }

def main():
    """Generate change ETH revert test vectors"""
    
    generator = ChangeETHRevertGenerator()
    
    # Create output directory
    output_dir = PROJECT_ROOT / "test" / "test_vectors" / "revert"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate change ETH revert vectors
    change_eth_reverts = generator.generate_change_eth_revert_vectors()
    
    # Generate remove change ETH revert vectors
    remove_change_eth_reverts = generator.generate_remove_change_eth_revert_vectors()
    
    # Generate confirm change ETH revert vectors
    confirm_change_eth_reverts = generator.generate_confirm_change_eth_revert_vectors()
    
    # Combine all sets of vectors
    all_vectors = {
        **change_eth_reverts,
        **remove_change_eth_reverts,
        **confirm_change_eth_reverts
    }
    
    # Write to file
    output_file = output_dir / "change_eth_revert_vectors.json"
    with open(output_file, "w") as f:
        json.dump(all_vectors, f, indent=2)
    
    print(f"Generated change ETH revert vectors: {output_file}")
    print("Change ETH revert test vectors generated successfully!")

if __name__ == "__main__":
    main() 
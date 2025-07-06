#!/usr/bin/env python3
"""
Unregistration Revert Test Vector Generator

This generator creates test vectors specifically designed to trigger revert conditions
in the PQRegistry contract's unregistration functionality.
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
    get_unregistration_intent_struct_hash,
    get_unregistration_confirmation_struct_hash,
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

class UnregistrationRevertGenerator:
    def __init__(self):
        self.actors = load_actors_config()
        
    def create_base_eth_message(self, pq_fingerprint, eth_nonce):
        """
        Create base ETH message for unregistration intent
        Format: "Intent to unregister from Epervier Fingerprint " + pqFingerprint + ethNonce
        This is signed by the ETH Address (no domain separator in content)
        """
        pattern = b"Intent to unregister from Epervier Fingerprint "
        message = (
            pattern +
            bytes.fromhex(pq_fingerprint[2:]) +  # Remove '0x' prefix
            eth_nonce.to_bytes(32, 'big')
        )
        return message

    def create_base_pq_message(self, eth_address, base_eth_message, v, r, s, pq_nonce):
        """
        Create base PQ message for unregistration intent
        Format: DOMAIN_SEPARATOR + "Intent to unregister from Epervier Fingerprint from address " + ethAddress + baseETHMessage + v + r + s + pqNonce
        """
        domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
        pattern = b"Intent to unregister from Epervier Fingerprint from address "
        eth_addr_bytes = bytes.fromhex(eth_address[2:])
        # base_eth_message is already bytes
        v_bytes = v.to_bytes(1, 'big')
        r_bytes = int(r, 16).to_bytes(32, 'big') if isinstance(r, str) else r.to_bytes(32, 'big')
        s_bytes = int(s, 16).to_bytes(32, 'big') if isinstance(s, str) else s.to_bytes(32, 'big')
        pq_nonce_bytes = pq_nonce.to_bytes(32, 'big')
        message = (
            domain_separator_bytes +
            pattern +
            eth_addr_bytes +
            base_eth_message +
            v_bytes +
            r_bytes +
            s_bytes +
            pq_nonce_bytes
        )
        return message

    def sign_eth_message(self, pq_fingerprint, eth_nonce, private_key):
        """Sign ETH unregistration intent message using EIP712"""
        # Use EIP712 helpers to get struct hash and digest
        struct_hash = get_unregistration_intent_struct_hash(pq_fingerprint, eth_nonce)
        domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
        digest = get_eip712_digest(domain_separator_bytes, struct_hash)
        signed = sign_eip712_message(digest, private_key)
        return signed

    def sign_with_pq_key(self, base_pq_message, pq_private_key_file):
        """Sign a message with PQ private key using sign_cli.py (real implementation)"""
        import tempfile
        import os
        # Write message to temp file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(base_pq_message)
            tmp.flush()
            tmp_path = tmp.name
        sign_cli = PROJECT_ROOT / "ETHFALCON/python-ref/sign_cli.py"
        privkey_path = PROJECT_ROOT / "test/test_keys" / pq_private_key_file
        venv_python = PROJECT_ROOT / "ETHFALCON/python-ref/myenv/bin/python3"
        cmd = [
            str(venv_python), str(sign_cli), "sign",
            f"--privkey={privkey_path}",
            f"--data={base_pq_message.hex()}",
            "--version=epervier"
        ]
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        os.unlink(tmp_path)
        print("PQ sign_cli output:")
        print(result.stdout)
        lines = result.stdout.splitlines()
        out = {}
        for line in lines:
            if line.startswith("salt:"):
                out["salt"] = line.split()[1]
            elif line.startswith("hint:"):
                out["hint"] = int(line.split()[1])
            elif line.startswith("cs1:"):
                out["cs1"] = [hex(int(x, 16)) for x in line.split()[1:]]
            elif line.startswith("cs2:"):
                out["cs2"] = [hex(int(x, 16)) for x in line.split()[1:]]
        if not all(k in out for k in ["salt", "hint", "cs1", "cs2"]):
            print("Failed to parse PQ signature components!")
            return None
        return out

    def sign_remove_unregistration_message(self, eth_address, pq_nonce, pq_private_key_file):
        """Sign PQ remove unregistration intent message"""
        # This is a stub. Actual implementation should call PQ signing logic.
        # Returns a dict with keys: salt, hint, cs1, cs2
        return self.sign_with_pq_key(b"", pq_private_key_file)

    def generate_submit_unregistration_revert_vectors(self) -> Dict[str, Any]:
        """Generate revert test vectors for submit unregistration intent"""
        print("Generating submit unregistration intent revert vectors...")
        vectors = []
        
        # Get actor addresses and keys
        alice = self.actors["alice"]
        bob = self.actors["bob"]
        charlie = self.actors["charlie"]
        
        # 1. Malformed message - wrong pattern at the start
        print("  Generating malformed message vector...")
        eth_nonce = 0
        pq_nonce = 0
        
        # Create valid base ETH message
        base_eth_message = self.create_base_eth_message(alice["pq_fingerprint"], eth_nonce)
        
        # Sign it with Alice's ETH key
        eth_sig = self.sign_eth_message(alice["pq_fingerprint"], eth_nonce, alice["eth_private_key"])
        
        # Create valid base PQ message
        base_pq_message = self.create_base_pq_message(
            alice["eth_address"], base_eth_message, eth_sig["v"], eth_sig["r"], eth_sig["s"], pq_nonce
        )
        
        # Sign with Alice's PQ key
        pq_sig = self.sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])
        
        # Create malformed message by corrupting the pattern (not the domain separator)
        domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
        wrong_pattern = b"Xntent to unregister from Epervier Fingerprint from address "
        # Compose the malformed message: valid domain separator + corrupted pattern + rest of message
        valid_pattern = b"Intent to unregister from Epervier Fingerprint from address "
        assert base_pq_message.startswith(domain_separator_bytes + valid_pattern), "Base PQ message does not start with expected pattern"
        malformed_pq_message = domain_separator_bytes + wrong_pattern + base_pq_message[len(domain_separator_bytes + valid_pattern):]
        assert len(malformed_pq_message) == len(base_pq_message), f"Malformed message must be {len(base_pq_message)} bytes"
        
        vectors.append({
            "test_name": "malformed_message",
            "description": "Test revert when PQ message has wrong pattern (not domain separator)",
            "actor": "alice",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": malformed_pq_message.hex(),
            "eth_signature": {
                "v": eth_sig["v"],
                "r": eth_sig["r"],
                "s": eth_sig["s"]
            },
            "pq_signature": {
                "salt": pq_sig["salt"],
                "cs1": pq_sig["cs1"],
                "cs2": pq_sig["cs2"],
                "hint": pq_sig["hint"]
            },
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        })
        
        # 2. Invalid ETH signature - corrupted r value
        print("  Generating invalid ETH signature vector...")
        eth_nonce = 2  # After complete registration (submit + confirm), nonce is 2
        pq_nonce = 2   # After complete registration (submit + confirm), nonce is 2
        
        base_eth_message = self.create_base_eth_message(alice["pq_fingerprint"], eth_nonce)
        eth_sig = self.sign_eth_message(alice["pq_fingerprint"], eth_nonce, alice["eth_private_key"])
        
        # Corrupt the r value
        corrupted_r = "0x" + "1" * 64  # All 1s instead of valid signature
        
        base_pq_message = self.create_base_pq_message(
            alice["eth_address"], base_eth_message, eth_sig["v"], corrupted_r, eth_sig["s"], pq_nonce
        )
        pq_sig = self.sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])
        
        vectors.append({
            "test_name": "invalid_eth_signature",
            "description": "Test revert when ETH signature has corrupted r value",
            "actor": "alice",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_signature": {
                "v": eth_sig["v"],
                "r": corrupted_r,
                "s": eth_sig["s"]
            },
            "pq_signature": {
                "salt": pq_sig["salt"],
                "cs1": pq_sig["cs1"],
                "cs2": pq_sig["cs2"],
                "hint": pq_sig["hint"]
            },
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        })
        
        # 3. Invalid PQ signature - corrupted cs1 values
        print("  Generating invalid PQ signature vector...")
        eth_nonce = 2  # After complete registration (submit + confirm), nonce is 2
        pq_nonce = 2   # After complete registration (submit + confirm), nonce is 2
        
        base_eth_message = self.create_base_eth_message(alice["pq_fingerprint"], eth_nonce)
        eth_sig = self.sign_eth_message(alice["pq_fingerprint"], eth_nonce, alice["eth_private_key"])
        base_pq_message = self.create_base_pq_message(
            alice["eth_address"], base_eth_message, eth_sig["v"], eth_sig["r"], eth_sig["s"], pq_nonce
        )
        pq_sig = self.sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])
        
        # Corrupt cs1 values
        corrupted_cs1 = ["0x" + "1" * 64] * 32  # All 1s instead of valid signature
        
        vectors.append({
            "test_name": "invalid_pq_signature",
            "description": "Test revert when PQ signature has corrupted cs1 values",
            "actor": "alice",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_signature": {
                "v": eth_sig["v"],
                "r": eth_sig["r"],
                "s": eth_sig["s"]
            },
            "pq_signature": {
                "salt": pq_sig["salt"],
                "cs1": corrupted_cs1,
                "cs2": pq_sig["cs2"],
                "hint": pq_sig["hint"]
            },
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        })
        
        # 4. ETH address not registered
        print("  Generating ETH address not registered vector...")
        eth_nonce = 0  # Charlie is not registered, so nonce is 0
        pq_nonce = 0   # Using Alice's PQ key, but nonce is 0 for unregistered address
        
        # Use Charlie's address (not registered) but Alice's PQ key
        base_eth_message = self.create_base_eth_message(alice["pq_fingerprint"], eth_nonce)
        eth_sig = self.sign_eth_message(alice["pq_fingerprint"], eth_nonce, charlie["eth_private_key"])  # Charlie's key
        base_pq_message = self.create_base_pq_message(
            charlie["eth_address"], base_eth_message, eth_sig["v"], eth_sig["r"], eth_sig["s"], pq_nonce  # Charlie's address
        )
        pq_sig = self.sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])
        
        vectors.append({
            "test_name": "eth_address_not_registered",
            "description": "Test revert when ETH address is not registered",
            "actor": "charlie",
            "eth_address": charlie["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_signature": {
                "v": eth_sig["v"],
                "r": eth_sig["r"],
                "s": eth_sig["s"]
            },
            "pq_signature": {
                "salt": pq_sig["salt"],
                "cs1": pq_sig["cs1"],
                "cs2": pq_sig["cs2"],
                "hint": pq_sig["hint"]
            },
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        })
        
        # 5. Change-ETH intent open for PQ
        print("  Generating change-ETH intent open vector...")
        eth_nonce = 2  # After complete registration (submit + confirm), nonce is 2
        pq_nonce = 2   # After complete registration (submit + confirm), nonce is 2
        
        # This test requires a change-ETH intent to be open first
        # The test will set up the change intent, then try to submit unregistration
        base_eth_message = self.create_base_eth_message(alice["pq_fingerprint"], eth_nonce)
        eth_sig = self.sign_eth_message(alice["pq_fingerprint"], eth_nonce, alice["eth_private_key"])
        base_pq_message = self.create_base_pq_message(
            alice["eth_address"], base_eth_message, eth_sig["v"], eth_sig["r"], eth_sig["s"], pq_nonce
        )
        pq_sig = self.sign_with_pq_key(base_pq_message, alice["pq_private_key_file"])
        
        vectors.append({
            "test_name": "change_eth_intent_open",
            "description": "Test revert when change-ETH intent is open for PQ fingerprint",
            "actor": "alice",
            "eth_address": alice["eth_address"],
            "pq_fingerprint": alice["pq_fingerprint"],
            "base_eth_message": base_eth_message.hex(),
            "pq_message": base_pq_message.hex(),
            "eth_signature": {
                "v": eth_sig["v"],
                "r": eth_sig["r"],
                "s": eth_sig["s"]
            },
            "pq_signature": {
                "salt": pq_sig["salt"],
                "cs1": pq_sig["cs1"],
                "cs2": pq_sig["cs2"],
                "hint": pq_sig["hint"]
            },
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        })

        return {
            "submit_unregistration_intent": vectors
        }

    def generate_remove_unregistration_revert_vectors(self) -> Dict[str, Any]:
        """Generate revert test vectors for remove unregistration intent (PQ controlled only)"""
        print("Generating remove unregistration intent revert vectors...")
        vectors = []
        
        # TODO: Implement all 8 revert scenarios:
        # 1. Malformed message
        # 2. Invalid PQ signature
        # 3. No pending intent
        # 4. Wrong PQ nonce
        # 5. Address mismatch
        # 6. Wrong domain separator
        # 7. Wrong PQ signer
        # 8. ETH address mismatch

        return {
            "remove_unregistration_intent": vectors
        }

    def generate_confirm_unregistration_revert_vectors(self) -> Dict[str, Any]:
        """Generate revert test vectors for confirm unregistration"""
        print("Generating confirm unregistration revert vectors...")
        vectors = []
        
        # TODO: Implement all 12 revert scenarios:
        # 1. Malformed message
        # 2. Invalid ETH signature
        # 3. Invalid PQ signature
        # 4. No pending intent
        # 5. Wrong ETH nonce
        # 6. Wrong PQ nonce
        # 7. Address mismatch
        # 8. Wrong domain separator
        # 9. Wrong ETH signer
        # 10. Wrong PQ signer
        # 11. ETH address mismatch
        # 12. PQ fingerprint mismatch

        return {
            "confirm_unregistration": vectors
        }

    def create_base_pq_confirm_message(self, eth_address, pq_nonce):
        """Create base PQ message for unregistration confirmation
        Format: DOMAIN_SEPARATOR + "Confirm unregistration from ETH Address " + ethAddress + pqNonce
        """
        domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])
        pattern = b"Confirm unregistration from ETH Address "
        eth_addr_bytes = bytes.fromhex(eth_address[2:])
        pq_nonce_bytes = pq_nonce.to_bytes(32, 'big')
        message = domain_separator_bytes + pattern + eth_addr_bytes + pq_nonce_bytes
        return message

    def create_eth_confirm_message(self, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
        """Create ETH message for unregistration confirmation
        Format: pattern + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
        """
        pattern = b"Confirm unregistration from Epervier Fingerprint "
        pq_fingerprint_bytes = bytes.fromhex(pq_fingerprint[2:])
        # base_pq_message is already bytes
        salt_bytes = bytes.fromhex(salt) if isinstance(salt, str) else salt
        cs1_bytes = b"".join(x.to_bytes(32, 'big') if isinstance(x, int) else int(x, 16).to_bytes(32, 'big') for x in cs1)
        cs2_bytes = b"".join(x.to_bytes(32, 'big') if isinstance(x, int) else int(x, 16).to_bytes(32, 'big') for x in cs2)
        hint_bytes = hint.to_bytes(32, 'big')
        eth_nonce_bytes = eth_nonce.to_bytes(32, 'big')
        message = (
            pattern +
            pq_fingerprint_bytes +
            base_pq_message +
            salt_bytes +
            cs1_bytes +
            cs2_bytes +
            hint_bytes +
            eth_nonce_bytes
        )
        return message

    def sign_eth_confirm_message(self, message_bytes, private_key, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
        """Sign ETH confirmation message using EIP712"""
        # This is a stub. Actual implementation should use EIP712 helpers for unregistration confirmation
        # Returns a dict with keys: v, r, s
        return {"v": 27, "r": "0x0", "s": "0x0"}

    def sign_eth_confirm_message_with_wrong_domain(self, message_bytes, private_key, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
        """Sign ETH confirmation message using EIP712 with wrong domain separator"""
        # This is a stub. Actual implementation should use EIP712 helpers with a wrong domain separator
        return {"v": 27, "r": "0x0", "s": "0x0"}

def main():
    """Generate unregistration revert test vectors"""
    
    generator = UnregistrationRevertGenerator()
    
    # Create output directory
    output_dir = PROJECT_ROOT / "test" / "test_vectors" / "revert"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate unregistration revert vectors
    submit_unregistration_reverts = generator.generate_submit_unregistration_revert_vectors()
    
    # Generate remove unregistration revert vectors
    remove_unregistration_reverts = generator.generate_remove_unregistration_revert_vectors()
    
    # Generate confirm unregistration revert vectors
    confirm_unregistration_reverts = generator.generate_confirm_unregistration_revert_vectors()
    
    # Combine all sets of vectors
    all_vectors = {
        **submit_unregistration_reverts,
        **remove_unregistration_reverts,
        **confirm_unregistration_reverts
    }
    
    # Write to file
    output_file = output_dir / "unregistration_revert_vectors.json"
    with open(output_file, "w") as f:
        json.dump(all_vectors, f, indent=2)
    
    print(f"Generated unregistration revert vectors: {output_file}")
    print("Unregistration revert test vectors generated successfully!")

if __name__ == "__main__":
    main() 
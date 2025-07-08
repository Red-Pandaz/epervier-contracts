#!/usr/bin/env python3
"""
Change ETH Address Removal Revert Vector Generator

This script generates test vectors for revert scenarios in change ETH address removal functions:
- removeChangeETHAddressIntentByETH (ETH-controlled removal)
- removeChangeETHAddressIntentByPQ (PQ-controlled removal)

The vectors cover various failure scenarios like wrong signatures, nonces, domain separators, etc.
"""

import json
import os
import sys
import subprocess
from typing import Dict, List, Any
from eth_account import Account
from eth_account.messages import encode_defunct
import hashlib
from pathlib import Path

# Add the parent directory to the path to import eip712_config
sys.path.append(str(Path(__file__).resolve().parents[2]))  # test/python
from eip712_config import DOMAIN_SEPARATOR

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[4]  # epervier-registry
ACTORS_CONFIG_PATH = PROJECT_ROOT / "test" / "test_keys" / "actors_config.json"

# Wrong domain separator for testing
WRONG_DOMAIN_SEPARATOR = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

def get_actor_config():
    """Load actor configuration from JSON file"""
    with open(ACTORS_CONFIG_PATH, "r") as f:
        config = json.load(f)
        return config["actors"]

def create_eth_remove_change_intent_message(pq_fingerprint, eth_nonce, domain_separator=DOMAIN_SEPARATOR):
    """Create ETH message for removing change intent"""
    pattern = b"Remove change intent from ETH Address "
    message = (
        bytes.fromhex(domain_separator[2:]) +  # Remove '0x' prefix
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, 'big')
    )
    return message

def create_pq_remove_change_intent_message(eth_address, pq_nonce, domain_separator=DOMAIN_SEPARATOR):
    """Create PQ message for removing change intent"""
    pattern = b"Remove change intent from ETH Address "
    message = (
        bytes.fromhex(domain_separator[2:]) +  # Remove '0x' prefix
        pattern +
        bytes.fromhex(eth_address[2:]) +  # Remove "0x" prefix
        pq_nonce.to_bytes(32, 'big')
    )
    return message

def create_epervier_signature(message, pq_private_key_file):
    """Create Epervier signature using sign_cli.py"""
    try:
        sign_cli = str(PROJECT_ROOT / "ETHFALCON" / "python-ref" / "sign_cli.py")
        privkey_path = str(PROJECT_ROOT / "test" / "test_keys" / pq_private_key_file)
        venv_python = str(PROJECT_ROOT / "ETHFALCON" / "python-ref" / "myenv" / "bin" / "python3")
        
        cmd = [
            venv_python, sign_cli, "sign",
            f"--privkey={privkey_path}",
            f"--data={message.hex()}",
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
                        if x and x.startswith('0x'):
                            try:
                                parsed.append(int(x[2:], 16))
                            except Exception as e:
                                print(f"Error parsing cs1 value '{x}': {e}")
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
                        if x and x.startswith('0x'):
                            try:
                                parsed.append(int(x[2:], 16))
                            except Exception as e:
                                print(f"Error parsing cs2 value '{x}': {e}")
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

def create_epervier_keypair():
    """Placeholder for create_epervier_keypair - not used in this generator"""
    pass

def generate_eth_removal_revert_vectors() -> List[Dict[str, Any]]:
    """Generate revert test vectors for removeChangeETHAddressIntentByETH"""
    
    actors = get_actor_config()
    alice = actors["alice"]
    bob = actors["bob"]
    charlie = actors["charlie"]
    
    # Create eth_account objects from private keys
    alice["eth_account"] = Account.from_key(alice["eth_private_key"])
    bob["eth_account"] = Account.from_key(bob["eth_private_key"])
    charlie["eth_account"] = Account.from_key(charlie["eth_private_key"])
    
    # Define nonces locally for different test scenarios
    alice_eth_nonce = 0
    bob_eth_nonce = 0
    charlie_eth_nonce = 0
    
    vectors = []
    
    # Vector 0: No pending change intent (try to remove when none exists)
    eth_message_0 = create_eth_remove_change_intent_message(
        alice["pq_fingerprint"], 
        alice_eth_nonce + 1  # Use future nonce
    )
    eth_signature_0 = alice["eth_account"].sign_message(encode_defunct(eth_message_0))
    
    vectors.append({
        "test_name": "no_pending_change_intent",
        "description": "Try to remove change intent when none exists for the PQ fingerprint",
        "pq_fingerprint": alice["pq_fingerprint"],
        "eth_nonce": alice_eth_nonce + 1,
        "eth_message": eth_message_0.hex(),
        "eth_signature": {
            "v": eth_signature_0.v,
            "r": hex(eth_signature_0.r),
            "s": hex(eth_signature_0.s)
        }
    })
    
    # Vector 1: Wrong domain separator
    eth_message_1 = create_eth_remove_change_intent_message(
        alice["pq_fingerprint"], 
        alice_eth_nonce + 1,
        domain_separator=WRONG_DOMAIN_SEPARATOR
    )
    eth_signature_1 = alice["eth_account"].sign_message(encode_defunct(eth_message_1))
    
    vectors.append({
        "test_name": "wrong_domain_separator",
        "description": "ETH message with wrong domain separator",
        "pq_fingerprint": alice["pq_fingerprint"],
        "eth_nonce": alice_eth_nonce + 1,
        "eth_message": eth_message_1.hex(),
        "eth_signature": {
            "v": eth_signature_1.v,
            "r": hex(eth_signature_1.r),
            "s": hex(eth_signature_1.s)
        }
    })
    
    # Vector 2: Wrong ETH nonce
    eth_message_2 = create_eth_remove_change_intent_message(
        alice["pq_fingerprint"], 
        alice_eth_nonce + 2  # Use wrong nonce
    )
    eth_signature_2 = alice["eth_account"].sign_message(encode_defunct(eth_message_2))
    
    vectors.append({
        "test_name": "wrong_eth_nonce",
        "description": "ETH message with wrong nonce",
        "pq_fingerprint": alice["pq_fingerprint"],
        "eth_nonce": alice_eth_nonce + 2,
        "eth_message": eth_message_2.hex(),
        "eth_signature": {
            "v": eth_signature_2.v,
            "r": hex(eth_signature_2.r),
            "s": hex(eth_signature_2.s)
        }
    })
    
    # Vector 3: Wrong signer (Bob signs Alice's removal)
    eth_message_3 = create_eth_remove_change_intent_message(
        alice["pq_fingerprint"], 
        alice_eth_nonce + 1
    )
    eth_signature_3 = bob["eth_account"].sign_message(encode_defunct(eth_message_3))
    
    vectors.append({
        "test_name": "wrong_signer",
        "description": "ETH message signed by wrong address (Bob signs Alice's removal)",
        "pq_fingerprint": alice["pq_fingerprint"],
        "eth_nonce": alice_eth_nonce + 1,
        "eth_message": eth_message_3.hex(),
        "eth_signature": {
            "v": eth_signature_3.v,
            "r": hex(eth_signature_3.r),
            "s": hex(eth_signature_3.s)
        }
    })
    
    # Vector 4: Malformed message (too short)
    malformed_message = b"Remove change intent from Epervier Fingerprint " + alice["pq_fingerprint"].encode()
    eth_signature_4 = alice["eth_account"].sign_message(encode_defunct(malformed_message))
    
    vectors.append({
        "test_name": "malformed_message",
        "description": "ETH message that's too short (missing nonce)",
        "pq_fingerprint": alice["pq_fingerprint"],
        "eth_nonce": alice_eth_nonce + 1,
        "eth_message": malformed_message.hex(),
        "eth_signature": {
            "v": eth_signature_4.v,
            "r": hex(eth_signature_4.r),
            "s": hex(eth_signature_4.s)
        }
    })
    
    # Vector 5: Invalid signature components
    eth_message_5 = create_eth_remove_change_intent_message(
        alice["pq_fingerprint"], 
        alice_eth_nonce + 1
    )
    
    vectors.append({
        "test_name": "invalid_signature",
        "description": "ETH message with invalid signature components",
        "pq_fingerprint": alice["pq_fingerprint"],
        "eth_nonce": alice_eth_nonce + 1,
        "eth_message": eth_message_5.hex(),
        "eth_signature": {
            "v": 27,  # Invalid v value
            "r": "0x1234567890123456789012345678901234567890123456789012345678901234",
            "s": "0x5678901234567890123456789012345678901234567890123456789012345678"
        }
    })
    
    # Vector 6: Wrong PQ fingerprint in message
    eth_message_6 = create_eth_remove_change_intent_message(
        bob["pq_fingerprint"],  # Use Bob's fingerprint instead of Alice's
        alice_eth_nonce + 1
    )
    eth_signature_6 = alice["eth_account"].sign_message(encode_defunct(eth_message_6))
    
    vectors.append({
        "test_name": "wrong_pq_fingerprint",
        "description": "ETH message with wrong PQ fingerprint (Bob's instead of Alice's)",
        "pq_fingerprint": bob["pq_fingerprint"],
        "eth_nonce": alice_eth_nonce + 1,
        "eth_message": eth_message_6.hex(),
        "eth_signature": {
            "v": eth_signature_6.v,
            "r": hex(eth_signature_6.r),
            "s": hex(eth_signature_6.s)
        }
    })
    
    return vectors

def generate_pq_removal_revert_vectors() -> List[Dict[str, Any]]:
    """Generate revert test vectors for removeChangeETHAddressIntentByPQ"""
    
    actors = get_actor_config()
    alice = actors["alice"]
    bob = actors["bob"]
    charlie = actors["charlie"]

    # Define nonces locally for different test scenarios
    alice_pq_nonce = 0
    bob_pq_nonce = 0
    charlie_pq_nonce = 0
    
    vectors = []
    
    # Vector 0: No pending change intent (try to remove when none exists)
    pq_message_0 = create_pq_remove_change_intent_message(
        alice["eth_address"],
        alice_pq_nonce + 1
    )
    pq_signature_0 = create_epervier_signature(pq_message_0, alice["pq_private_key_file"])
    
    vectors.append({
        "test_name": "no_pending_change_intent",
        "description": "Try to remove change intent when none exists for the PQ fingerprint",
        "eth_address": alice["eth_address"],
        "pq_nonce": alice_pq_nonce + 1,
        "pq_message": pq_message_0.hex(),
        "pq_signature": {
            "salt": pq_signature_0["salt"],
            "cs1": pq_signature_0["cs1"],
            "cs2": pq_signature_0["cs2"],
            "hint": pq_signature_0["hint"]
        }
    })
    
    # Vector 1: Wrong domain separator
    pq_message_1 = create_pq_remove_change_intent_message(
        alice["eth_address"],
        alice_pq_nonce + 1,
        domain_separator=WRONG_DOMAIN_SEPARATOR
    )
    pq_signature_1 = create_epervier_signature(pq_message_1, alice["pq_private_key_file"])
    
    vectors.append({
        "test_name": "wrong_domain_separator",
        "description": "PQ message with wrong domain separator",
        "eth_address": alice["eth_address"],
        "pq_nonce": alice_pq_nonce + 1,
        "pq_message": pq_message_1.hex(),
        "pq_signature": {
            "salt": pq_signature_1["salt"],
            "cs1": pq_signature_1["cs1"],
            "cs2": pq_signature_1["cs2"],
            "hint": pq_signature_1["hint"]
        }
    })
    
    # Vector 2: Wrong PQ nonce
    pq_message_2 = create_pq_remove_change_intent_message(
        alice["eth_address"],
        alice_pq_nonce + 2  # Use wrong nonce
    )
    pq_signature_2 = create_epervier_signature(pq_message_2, alice["pq_private_key_file"])
    
    vectors.append({
        "test_name": "wrong_pq_nonce",
        "description": "PQ message with wrong nonce",
        "eth_address": alice["eth_address"],
        "pq_nonce": alice_pq_nonce + 2,
        "pq_message": pq_message_2.hex(),
        "pq_signature": {
            "salt": pq_signature_2["salt"],
            "cs1": pq_signature_2["cs1"],
            "cs2": pq_signature_2["cs2"],
            "hint": pq_signature_2["hint"]
        }
    })
    
    # Vector 3: Wrong signer (Bob signs Alice's removal)
    pq_message_3 = create_pq_remove_change_intent_message(
        alice["eth_address"],
        alice_pq_nonce + 1
    )
    pq_signature_3 = create_epervier_signature(pq_message_3, bob["pq_private_key_file"])
    
    vectors.append({
        "test_name": "wrong_signer",
        "description": "PQ message signed by wrong key (Bob signs Alice's removal)",
        "eth_address": alice["eth_address"],
        "pq_nonce": alice_pq_nonce + 1,
        "pq_message": pq_message_3.hex(),
        "pq_signature": {
            "salt": pq_signature_3["salt"],
            "cs1": pq_signature_3["cs1"],
            "cs2": pq_signature_3["cs2"],
            "hint": pq_signature_3["hint"]
        }
    })
    
    # Vector 4: Invalid PQ signature
    pq_message_4 = create_pq_remove_change_intent_message(
        alice["eth_address"],
        alice_pq_nonce + 1
    )
    
    vectors.append({
        "test_name": "invalid_pq_signature",
        "description": "PQ message with invalid signature components",
        "eth_address": alice["eth_address"],
        "pq_nonce": alice_pq_nonce + 1,
        "pq_message": pq_message_4.hex(),
        "pq_signature": {
            "salt": "0x1234567890123456789012345678901234567890123456789012345678901234",
            "cs1": ["0x1234567890123456789012345678901234567890123456789012345678901234"],
            "cs2": ["0x5678901234567890123456789012345678901234567890123456789012345678"],
            "hint": 999
        }
    })
    
    # Vector 5: Wrong ETH address in message
    pq_message_5 = create_pq_remove_change_intent_message(
        bob["eth_address"],  # Use Bob's address instead of Alice's
        alice_pq_nonce + 1
    )
    pq_signature_5 = create_epervier_signature(pq_message_5, alice["pq_private_key_file"])
    
    vectors.append({
        "test_name": "wrong_eth_address",
        "description": "PQ message with wrong ETH address (Bob's instead of Alice's)",
        "eth_address": bob["eth_address"],
        "pq_nonce": alice_pq_nonce + 1,
        "pq_message": pq_message_5.hex(),
        "pq_signature": {
            "salt": pq_signature_5["salt"],
            "cs1": pq_signature_5["cs1"],
            "cs2": pq_signature_5["cs2"],
            "hint": pq_signature_5["hint"]
        }
    })
    
    return vectors

def main():
    """Generate all revert test vectors and save to JSON file"""
    
    print("Generating change ETH address removal revert test vectors...")
    
    # Generate vectors for both removal functions
    eth_removal_vectors = generate_eth_removal_revert_vectors()
    pq_removal_vectors = generate_pq_removal_revert_vectors()
    
    # Create the output structure
    output = {
        "remove_change_intent_eth_reverts": eth_removal_vectors,
        "remove_change_intent_pq_reverts": pq_removal_vectors
    }
    
    # Save to file
    output_file = "test/test_vectors/revert/change_eth_removal_revert_vectors.json"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"Generated {len(eth_removal_vectors)} ETH removal revert vectors")
    print(f"Generated {len(pq_removal_vectors)} PQ removal revert vectors")
    print(f"Saved to {output_file}")

if __name__ == "__main__":
    main() 
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
from typing import Dict, List, Any
from eth_account import Account
from eth_account.messages import encode_defunct
import hashlib

# Add the parent directory to the path to import the common module
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from common.actor_config import get_actor_config
from common.epervier_utils import create_epervier_signature, create_epervier_keypair
from common.message_utils import (
    create_eth_remove_change_intent_message,
    create_pq_remove_change_intent_message,
    DOMAIN_SEPARATOR,
    WRONG_DOMAIN_SEPARATOR
)

def generate_eth_removal_revert_vectors() -> List[Dict[str, Any]]:
    """Generate revert test vectors for removeChangeETHAddressIntentByETH"""
    
    actors = get_actor_config()
    alice = actors["alice"]
    bob = actors["bob"]
    charlie = actors["charlie"]
    
    vectors = []
    
    # Vector 0: No pending change intent (try to remove when none exists)
    eth_message_0 = create_eth_remove_change_intent_message(
        alice["pq_fingerprint"], 
        alice["eth_nonce"] + 1  # Use future nonce
    )
    eth_signature_0 = alice["eth_account"].sign_message(encode_defunct(eth_message_0))
    
    vectors.append({
        "test_name": "no_pending_change_intent",
        "description": "Try to remove change intent when none exists for the PQ fingerprint",
        "pq_fingerprint": alice["pq_fingerprint"],
        "eth_nonce": alice["eth_nonce"] + 1,
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
        alice["eth_nonce"] + 1,
        domain_separator=WRONG_DOMAIN_SEPARATOR
    )
    eth_signature_1 = alice["eth_account"].sign_message(encode_defunct(eth_message_1))
    
    vectors.append({
        "test_name": "wrong_domain_separator",
        "description": "ETH message with wrong domain separator",
        "pq_fingerprint": alice["pq_fingerprint"],
        "eth_nonce": alice["eth_nonce"] + 1,
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
        alice["eth_nonce"] + 2  # Use wrong nonce
    )
    eth_signature_2 = alice["eth_account"].sign_message(encode_defunct(eth_message_2))
    
    vectors.append({
        "test_name": "wrong_eth_nonce",
        "description": "ETH message with wrong nonce",
        "pq_fingerprint": alice["pq_fingerprint"],
        "eth_nonce": alice["eth_nonce"] + 2,
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
        alice["eth_nonce"] + 1
    )
    eth_signature_3 = bob["eth_account"].sign_message(encode_defunct(eth_message_3))
    
    vectors.append({
        "test_name": "wrong_signer",
        "description": "ETH message signed by wrong address (Bob signs Alice's removal)",
        "pq_fingerprint": alice["pq_fingerprint"],
        "eth_nonce": alice["eth_nonce"] + 1,
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
        "eth_nonce": alice["eth_nonce"] + 1,
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
        alice["eth_nonce"] + 1
    )
    
    vectors.append({
        "test_name": "invalid_signature",
        "description": "ETH message with invalid signature components",
        "pq_fingerprint": alice["pq_fingerprint"],
        "eth_nonce": alice["eth_nonce"] + 1,
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
        alice["eth_nonce"] + 1
    )
    eth_signature_6 = alice["eth_account"].sign_message(encode_defunct(eth_message_6))
    
    vectors.append({
        "test_name": "wrong_pq_fingerprint",
        "description": "ETH message with wrong PQ fingerprint (Bob's instead of Alice's)",
        "pq_fingerprint": bob["pq_fingerprint"],
        "eth_nonce": alice["eth_nonce"] + 1,
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
    
    vectors = []
    
    # Vector 0: No pending change intent (try to remove when none exists)
    pq_message_0 = create_pq_remove_change_intent_message(
        alice["eth_address"],
        alice["pq_nonce"] + 1
    )
    pq_signature_0 = create_epervier_signature(pq_message_0, alice["pq_private_key"])
    
    vectors.append({
        "test_name": "no_pending_change_intent",
        "description": "Try to remove change intent when none exists for the PQ fingerprint",
        "eth_address": alice["eth_address"],
        "pq_nonce": alice["pq_nonce"] + 1,
        "pq_message": pq_message_0.hex(),
        "pq_signature": {
            "salt": pq_signature_0["salt"].hex(),
            "cs1": [hex(x) for x in pq_signature_0["cs1"]],
            "cs2": [hex(x) for x in pq_signature_0["cs2"]],
            "hint": pq_signature_0["hint"]
        }
    })
    
    # Vector 1: Wrong domain separator
    pq_message_1 = create_pq_remove_change_intent_message(
        alice["eth_address"],
        alice["pq_nonce"] + 1,
        domain_separator=WRONG_DOMAIN_SEPARATOR
    )
    pq_signature_1 = create_epervier_signature(pq_message_1, alice["pq_private_key"])
    
    vectors.append({
        "test_name": "wrong_domain_separator",
        "description": "PQ message with wrong domain separator",
        "eth_address": alice["eth_address"],
        "pq_nonce": alice["pq_nonce"] + 1,
        "pq_message": pq_message_1.hex(),
        "pq_signature": {
            "salt": pq_signature_1["salt"].hex(),
            "cs1": [hex(x) for x in pq_signature_1["cs1"]],
            "cs2": [hex(x) for x in pq_signature_1["cs2"]],
            "hint": pq_signature_1["hint"]
        }
    })
    
    # Vector 2: Wrong PQ nonce
    pq_message_2 = create_pq_remove_change_intent_message(
        alice["eth_address"],
        alice["pq_nonce"] + 2  # Use wrong nonce
    )
    pq_signature_2 = create_epervier_signature(pq_message_2, alice["pq_private_key"])
    
    vectors.append({
        "test_name": "wrong_pq_nonce",
        "description": "PQ message with wrong nonce",
        "eth_address": alice["eth_address"],
        "pq_nonce": alice["pq_nonce"] + 2,
        "pq_message": pq_message_2.hex(),
        "pq_signature": {
            "salt": pq_signature_2["salt"].hex(),
            "cs1": [hex(x) for x in pq_signature_2["cs1"]],
            "cs2": [hex(x) for x in pq_signature_2["cs2"]],
            "hint": pq_signature_2["hint"]
        }
    })
    
    # Vector 3: Wrong signer (Bob signs Alice's removal)
    pq_message_3 = create_pq_remove_change_intent_message(
        alice["eth_address"],
        alice["pq_nonce"] + 1
    )
    pq_signature_3 = create_epervier_signature(pq_message_3, bob["pq_private_key"])
    
    vectors.append({
        "test_name": "wrong_signer",
        "description": "PQ message signed by wrong key (Bob signs Alice's removal)",
        "eth_address": alice["eth_address"],
        "pq_nonce": alice["pq_nonce"] + 1,
        "pq_message": pq_message_3.hex(),
        "pq_signature": {
            "salt": pq_signature_3["salt"].hex(),
            "cs1": [hex(x) for x in pq_signature_3["cs1"]],
            "cs2": [hex(x) for x in pq_signature_3["cs2"]],
            "hint": pq_signature_3["hint"]
        }
    })
    
    # Vector 4: Malformed message (too short)
    malformed_message = b"Remove change intent from ETH Address " + alice["eth_address"].encode()
    pq_signature_4 = create_epervier_signature(malformed_message, alice["pq_private_key"])
    
    vectors.append({
        "test_name": "malformed_message",
        "description": "PQ message that's too short (missing nonce)",
        "eth_address": alice["eth_address"],
        "pq_nonce": alice["pq_nonce"] + 1,
        "pq_message": malformed_message.hex(),
        "pq_signature": {
            "salt": pq_signature_4["salt"].hex(),
            "cs1": [hex(x) for x in pq_signature_4["cs1"]],
            "cs2": [hex(x) for x in pq_signature_4["cs2"]],
            "hint": pq_signature_4["hint"]
        }
    })
    
    # Vector 5: Invalid signature components
    pq_message_5 = create_pq_remove_change_intent_message(
        alice["eth_address"],
        alice["pq_nonce"] + 1
    )
    
    vectors.append({
        "test_name": "invalid_signature",
        "description": "PQ message with invalid signature components",
        "eth_address": alice["eth_address"],
        "pq_nonce": alice["pq_nonce"] + 1,
        "pq_message": pq_message_5.hex(),
        "pq_signature": {
            "salt": "0" * 80,  # All zeros
            "cs1": ["0x0"] * 32,  # All zeros
            "cs2": ["0x0"] * 32,  # All zeros
            "hint": 0  # Invalid hint
        }
    })
    
    # Vector 6: Wrong message format (wrong pattern text)
    wrong_pattern_message = DOMAIN_SEPARATOR + b"Wrong pattern text " + alice["eth_address"].encode() + (alice["pq_nonce"] + 1).to_bytes(32, "big")
    pq_signature_6 = create_epervier_signature(wrong_pattern_message, alice["pq_private_key"])
    
    vectors.append({
        "test_name": "wrong_message_format",
        "description": "PQ message with wrong pattern text",
        "eth_address": alice["eth_address"],
        "pq_nonce": alice["pq_nonce"] + 1,
        "pq_message": wrong_pattern_message.hex(),
        "pq_signature": {
            "salt": pq_signature_6["salt"].hex(),
            "cs1": [hex(x) for x in pq_signature_6["cs1"]],
            "cs2": [hex(x) for x in pq_signature_6["cs2"]],
            "hint": pq_signature_6["hint"]
        }
    })
    
    # Vector 7: Wrong ETH address in message
    pq_message_7 = create_pq_remove_change_intent_message(
        bob["eth_address"],  # Use Bob's address instead of Alice's
        alice["pq_nonce"] + 1
    )
    pq_signature_7 = create_epervier_signature(pq_message_7, alice["pq_private_key"])
    
    vectors.append({
        "test_name": "wrong_eth_address",
        "description": "PQ message with wrong ETH address (Bob's instead of Alice's)",
        "eth_address": bob["eth_address"],
        "pq_nonce": alice["pq_nonce"] + 1,
        "pq_message": pq_message_7.hex(),
        "pq_signature": {
            "salt": pq_signature_7["salt"].hex(),
            "cs1": [hex(x) for x in pq_signature_7["cs1"]],
            "cs2": [hex(x) for x in pq_signature_7["cs2"]],
            "hint": pq_signature_7["hint"]
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
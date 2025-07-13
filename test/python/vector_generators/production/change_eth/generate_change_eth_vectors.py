#!/usr/bin/env python3
"""
Generate change ETH address vectors for Tests 4 and 5
"""

import json
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import (
    get_actor_config, 
    create_eth_message, 
    create_pq_message, 
    sign_eth_message, 
    sign_pq_message,
    pack_eth_change_intent_message,
    pack_pq_change_cancel_message,
    pack_eth_change_cancel_message,
    pack_pq_change_confirmation_message
)

def generate_change_eth_vectors():
    """Generate change ETH address vectors for Tests 4 and 5"""
    
    # Load actor configurations
    alice = get_actor_config("alice")
    bob = get_actor_config("bob") 
    charlie = get_actor_config("charlie")
    
    vectors = {
        "change_eth_intent": [],
        "change_eth_cancel_pq": [],
        "change_eth_cancel_eth": [],
        "change_eth_confirmation": []
    }
    
    # Test 4 and 5: AlicePQ changes AliceETH to BobETH, then to CharlieETH after cancellation
    
    # Step 1: AlicePQ submits change intent to BobETH (nonce 1)
    print("Generating change intent to BobETH...")
    eth_message_1 = pack_eth_change_intent_message(
        eth_nonce=1,
        pq_fingerprint=alice["pq_fingerprint"],
        new_eth_address=bob["eth_address"],
        pq_salt=alice["pq_salt"],
        pq_cs1=alice["pq_cs1"],
        pq_cs2=alice["pq_cs2"],
        pq_hint=alice["pq_hint"]
    )
    
    eth_signature_1 = sign_eth_message(eth_message_1, bob["eth_private_key"])
    
    vectors["change_eth_intent"].append({
        "eth_message": eth_message_1.hex(),
        "eth_signature": {
            "v": eth_signature_1["v"],
            "r": eth_signature_1["r"],
            "s": eth_signature_1["s"]
        },
        "pq_signature": {
            "salt": alice["pq_salt"].hex(),
            "cs1": [str(x) for x in alice["pq_cs1"]],
            "cs2": [str(x) for x in alice["pq_cs2"]],
            "hint": str(alice["pq_hint"])
        }
    })
    
    # Step 2: AlicePQ cancels the change intent (PQ nonce 2)
    print("Generating PQ cancel message...")
    pq_cancel_message = pack_pq_change_cancel_message(
        pq_nonce=2,
        eth_address=bob["eth_address"]
    )
    
    pq_cancel_signature = sign_pq_message(pq_cancel_message, alice["pq_private_key"])
    
    vectors["change_eth_cancel_pq"].append({
        "pq_message": pq_cancel_message.hex(),
        "pq_signature": {
            "salt": pq_cancel_signature["salt"].hex(),
            "cs1": [str(x) for x in pq_cancel_signature["cs1"]],
            "cs2": [str(x) for x in pq_cancel_signature["cs2"]],
            "hint": str(pq_cancel_signature["hint"])
        }
    })
    
    # Step 3: BobETH cancels the change intent (ETH nonce 2)
    print("Generating ETH cancel message...")
    eth_cancel_message = pack_eth_change_cancel_message(
        eth_nonce=2,
        pq_fingerprint=alice["pq_fingerprint"]
    )
    
    eth_cancel_signature = sign_eth_message(eth_cancel_message, bob["eth_private_key"])
    
    vectors["change_eth_cancel_eth"].append({
        "eth_message": eth_cancel_message.hex(),
        "eth_signature": {
            "v": eth_cancel_signature["v"],
            "r": eth_cancel_signature["r"],
            "s": eth_cancel_signature["s"]
        }
    })
    
    # Step 4: AlicePQ submits new change intent to CharlieETH (nonce 3)
    print("Generating change intent to CharlieETH...")
    eth_message_2 = pack_eth_change_intent_message(
        eth_nonce=1,  # Charlie's ETH nonce starts at 1
        pq_fingerprint=alice["pq_fingerprint"],
        new_eth_address=charlie["eth_address"],
        pq_salt=alice["pq_salt"],
        pq_cs1=alice["pq_cs1"],
        pq_cs2=alice["pq_cs2"],
        pq_hint=alice["pq_hint"]
    )
    
    eth_signature_2 = sign_eth_message(eth_message_2, charlie["eth_private_key"])
    
    vectors["change_eth_intent"].append({
        "eth_message": eth_message_2.hex(),
        "eth_signature": {
            "v": eth_signature_2["v"],
            "r": eth_signature_2["r"],
            "s": eth_signature_2["s"]
        },
        "pq_signature": {
            "salt": alice["pq_salt"].hex(),
            "cs1": [str(x) for x in alice["pq_cs1"]],
            "cs2": [str(x) for x in alice["pq_cs2"]],
            "hint": str(alice["pq_hint"])
        }
    })
    
    # Step 5: AlicePQ confirms the change to CharlieETH (PQ nonce 4)
    print("Generating change confirmation message...")
    pq_confirm_message = pack_pq_change_confirmation_message(
        pq_nonce=4,
        eth_address=charlie["eth_address"],
        eth_nonce=2,  # Charlie's ETH nonce after confirmation
        eth_salt=charlie["eth_salt"],
        eth_cs1=charlie["eth_cs1"],
        eth_cs2=charlie["eth_cs2"],
        eth_hint=charlie["eth_hint"]
    )
    
    pq_confirm_signature = sign_pq_message(pq_confirm_message, alice["pq_private_key"])
    
    vectors["change_eth_confirmation"].append({
        "pq_message": pq_confirm_message.hex(),
        "pq_signature": {
            "salt": pq_confirm_signature["salt"].hex(),
            "cs1": [str(x) for x in pq_confirm_signature["cs1"]],
            "cs2": [str(x) for x in pq_confirm_signature["cs2"]],
            "hint": str(pq_confirm_signature["hint"])
        }
    })
    
    return vectors

def main():
    """Generate and save change ETH vectors"""
    print("Generating change ETH address vectors for Tests 4 and 5...")
    
    vectors = generate_change_eth_vectors()
    
    # Save to files
    output_dir = "test/test_vectors"
    os.makedirs(output_dir, exist_ok=True)
    
    # Save intent vectors
    with open(f"{output_dir}/change_eth_intent_vectors.json", "w") as f:
        json.dump(vectors, f, indent=2)
    
    # Save confirmation vectors separately
    confirmation_vectors = {
        "change_eth_confirmation": vectors["change_eth_confirmation"]
    }
    with open(f"{output_dir}/change_eth_confirmation_vectors.json", "w") as f:
        json.dump(confirmation_vectors, f, indent=2)
    
    print(f"Generated vectors saved to:")
    print(f"  {output_dir}/change_eth_intent_vectors.json")
    print(f"  {output_dir}/change_eth_confirmation_vectors.json")
    
    # Print summary
    print("\nVector summary:")
    print(f"  Change ETH intents: {len(vectors['change_eth_intent'])}")
    print(f"  PQ cancel messages: {len(vectors['change_eth_cancel_pq'])}")
    print(f"  ETH cancel messages: {len(vectors['change_eth_cancel_eth'])}")
    print(f"  Change confirmations: {len(vectors['change_eth_confirmation'])}")

if __name__ == "__main__":
    main() 
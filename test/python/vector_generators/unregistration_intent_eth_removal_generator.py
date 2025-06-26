import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak

print("Script loaded successfully!")

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[3]  # epervier-registry
ACTORS_CONFIG_PATH = PROJECT_ROOT / "test_keys/actors_config.json"
OUTPUT_PATH = PROJECT_ROOT / "test/test_vectors/unregistration_intent_eth_removal_vectors.json"
DOMAIN_SEPARATOR = keccak(b"PQRegistry")

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')


def load_actors_config():
    # Load the actors config JSON
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]


def build_eth_remove_unregistration_intent_message(domain_separator, pq_fingerprint, eth_nonce):
    # DOMAIN_SEPARATOR + "Remove unregistration intent from Epervier fingerprint " + pqFingerprint + ethNonce
    # This matches ETHRemoveUnregistrationIntentMessage in schema
    pattern = b"Remove unregistration intent from Epervier fingerprint "
    return domain_separator + pattern + bytes.fromhex(pq_fingerprint[2:]) + int_to_bytes32(eth_nonce)


def sign_with_eth_key(eth_message, eth_private_key):
    # Use Ethereum's personal_sign format
    eth_message_length = len(eth_message)
    eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + eth_message
    eth_message_hash = keccak(eth_signed_message)
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(eth_message_hash, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}


def main():
    print("Starting ETH-controlled unregistration intent removal vector generation...")
    actors = load_actors_config()
    print(f"Loaded {len(actors)} actors from config")
    vectors = []
    
    for actor_name, actor in actors.items():
        print(f"Processing {actor_name.capitalize()}: {actor['eth_address']}")
        eth_address = actor["eth_address"]
        eth_private_key = actor["eth_private_key"]
        pq_fingerprint = actor["pq_fingerprint"]
        eth_nonce = 0
        
        # Generate ETH-controlled remove unregistration intent
        print("Generating ETH remove unregistration intent...")
        eth_remove_unreg_message = build_eth_remove_unregistration_intent_message(DOMAIN_SEPARATOR, pq_fingerprint, eth_nonce)
        eth_remove_unreg_sig = sign_with_eth_key(eth_remove_unreg_message, eth_private_key)
        
        # Collect vector for this actor
        vector = {
            "actor": actor_name,
            "eth_address": eth_address,
            "pq_fingerprint": pq_fingerprint,
            "eth_remove_unregistration_intent": {
                "message": eth_remove_unreg_message.hex(),
                "signature": eth_remove_unreg_sig,
                "eth_nonce": eth_nonce
            }
        }
        vectors.append(vector)
    
    print(f"Writing {len(vectors)} vectors to {OUTPUT_PATH}")
    with open(OUTPUT_PATH, "w") as f:
        json.dump({"unregistration_intent_eth_removal": vectors}, f, indent=2)
    print("ETH-controlled unregistration intent removal vector generation complete!")

if __name__ == "__main__":
    main() 
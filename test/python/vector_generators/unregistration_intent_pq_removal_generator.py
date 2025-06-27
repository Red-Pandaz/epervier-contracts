import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak

print("Script loaded successfully!")

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[3]  # epervier-registry
ACTORS_CONFIG_PATH = PROJECT_ROOT / "test/test_keys/actors_config.json"
OUTPUT_PATH = PROJECT_ROOT / "test/test_vectors/unregistration_removal_vectors.json"
DOMAIN_SEPARATOR = keccak(b"PQRegistry")

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')


def load_actors_config():
    # Load the actors config JSON
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]


def build_pq_remove_unregistration_intent_message(domain_separator, eth_address, pq_nonce):
    # DOMAIN_SEPARATOR + "Remove unregistration intent from ETH Address " + ethAddress + pqNonce
    # This matches PQRemoveUnregistrationIntentMessage in schema
    pattern = b"Remove unregistration intent from ETH Address "
    return domain_separator + pattern + bytes.fromhex(eth_address[2:]) + int_to_bytes32(pq_nonce)


def sign_with_pq_key(pq_message, pq_private_key_file):
    # Use sign_cli.py to sign the PQ message
    from tempfile import NamedTemporaryFile
    import os
    # Write message to temp file
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(pq_message)
        tmp.flush()
        tmp_path = tmp.name
    
    sign_cli = PROJECT_ROOT / "ETHFALCON/python-ref/sign_cli.py"
    privkey_path = PROJECT_ROOT / "test/test_keys" / pq_private_key_file
    venv_python = PROJECT_ROOT / "ETHFALCON/python-ref/myenv/bin/python3"

    cmd = [
        str(venv_python), str(sign_cli), "sign",
        f"--privkey={privkey_path}",
        f"--data={pq_message.hex()}",
        "--version=epervier"
    ]
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    os.unlink(tmp_path)
    print("PQ sign_cli output:")
    print(result.stdout)
    # Parse output for salt, hint, cs1, cs2
    lines = result.stdout.splitlines()
    out = {}
    for line in lines:
        if line.startswith("salt:"):
            out["salt"] = bytes.fromhex(line.split()[1])
        elif line.startswith("hint:"):
            out["hint"] = int(line.split()[1])
        elif line.startswith("cs1:"):
            out["cs1"] = [int(x, 16) for x in line.split()[1:]]
        elif line.startswith("cs2:"):
            out["cs2"] = [int(x, 16) for x in line.split()[1:]]
    if not all(k in out for k in ["salt", "hint", "cs1", "cs2"]):
        print("Failed to parse PQ signature components!")
        return None
    return out


def main():
    print("Starting PQ-controlled unregistration intent removal vector generation...")
    actors = load_actors_config()
    print(f"Loaded {len(actors)} actors from config")
    vectors = []
    
    for actor_name, actor in actors.items():
        print(f"Processing {actor_name.capitalize()}: {actor['eth_address']}")
        eth_address = actor["eth_address"]
        pq_private_key_file = actor["pq_private_key_file"]
        pq_fingerprint = actor["pq_fingerprint"]
        pq_nonce = 3  # After unregistration intent submission
        
        # Generate PQ-controlled remove unregistration intent
        print("Generating PQ remove unregistration intent...")
        pq_remove_unreg_message = build_pq_remove_unregistration_intent_message(DOMAIN_SEPARATOR, eth_address, pq_nonce)
        pq_remove_unreg_sig = sign_with_pq_key(pq_remove_unreg_message, pq_private_key_file)
        
        if pq_remove_unreg_sig is None:
            print(f"Failed to generate PQ signature for {actor_name}!")
            continue
        
        # Collect vector for this actor
        vector = {
            "actor": actor_name,
            "eth_address": eth_address,
            "pq_fingerprint": pq_fingerprint,
            "pq_remove_unregistration_intent": {
                "message": pq_remove_unreg_message.hex(),
                "signature": {
                    "salt": pq_remove_unreg_sig["salt"].hex(),
                    "cs1": [hex(x) for x in pq_remove_unreg_sig["cs1"]],
                    "cs2": [hex(x) for x in pq_remove_unreg_sig["cs2"]],
                    "hint": pq_remove_unreg_sig["hint"]
                },
                "pq_nonce": pq_nonce
            }
        }
        vectors.append(vector)
    
    print(f"Writing {len(vectors)} vectors to {OUTPUT_PATH}")
    with open(OUTPUT_PATH, "w") as f:
        json.dump({"remove_intent": vectors}, f, indent=2)
    print("PQ-controlled unregistration intent removal vector generation complete!")

if __name__ == "__main__":
    main() 
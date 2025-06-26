import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak

print("Script loaded successfully!")

ACTORS_CONFIG_PATH = Path("test/test_keys/actors_config.json")
OUTPUT_PATH = Path("test/test_vectors/remove_intent_vectors.json")
DOMAIN_SEPARATOR = keccak(b"PQRegistry")

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')


def load_actors_config():
    # Load the actors config JSON
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]


def build_eth_remove_registration_intent_message(domain_separator, pq_fingerprint, eth_nonce):
    # DOMAIN_SEPARATOR + "Remove registration intent from Epervier fingerprint " + pqFingerprint + ethNonce
    # This matches ETHRemoveRegistrationIntentMessage in schema (44 chars pattern)
    pattern = b"Remove registration intent from Epervier fingerprint "
    return domain_separator + pattern + bytes.fromhex(pq_fingerprint[2:]) + int_to_bytes32(eth_nonce)


def build_pq_remove_registration_intent_message(domain_separator, eth_address, pq_nonce):
    # DOMAIN_SEPARATOR + "Remove registration intent from ETH address " + ethAddress + pqNonce
    # This matches PQRemoveRegistrationIntentMessage in schema (36 chars pattern)
    pattern = b"Remove registration intent from ETH address "
    return domain_separator + pattern + bytes.fromhex(eth_address[2:]) + int_to_bytes32(pq_nonce)


def build_eth_remove_change_intent_message(domain_separator, pq_fingerprint, eth_nonce):
    # DOMAIN_SEPARATOR + "Remove change intent from Epervier fingerprint " + pqFingerprint + ethNonce
    # This matches ETHRemoveChangeIntentMessage in schema (36 chars pattern)
    pattern = b"Remove change intent from Epervier fingerprint "
    return domain_separator + pattern + bytes.fromhex(pq_fingerprint[2:]) + int_to_bytes32(eth_nonce)


def build_pq_remove_change_intent_message(domain_separator, eth_address, pq_nonce):
    # DOMAIN_SEPARATOR + "Remove change intent from ETH address " + ethAddress + pqNonce
    # This matches PQRemoveChangeIntentMessage in schema (35 chars pattern)
    pattern = b"Remove change intent from ETH address "
    return domain_separator + pattern + bytes.fromhex(eth_address[2:]) + int_to_bytes32(pq_nonce)


def build_eth_remove_unregistration_intent_message(domain_separator, pq_fingerprint, eth_nonce):
    # DOMAIN_SEPARATOR + "Remove unregistration intent from Epervier fingerprint " + pqFingerprint + ethNonce
    # This matches ETHRemoveUnregistrationIntentMessage in schema (40 chars pattern)
    pattern = b"Remove unregistration intent from Epervier fingerprint "
    return domain_separator + pattern + bytes.fromhex(pq_fingerprint[2:]) + int_to_bytes32(eth_nonce)


def build_pq_remove_unregistration_intent_message(domain_separator, eth_address, pq_nonce):
    # DOMAIN_SEPARATOR + "Remove unregistration intent from ETH address " + ethAddress + pqNonce
    # This matches PQRemoveUnregistrationIntentMessage in schema (40 chars pattern)
    pattern = b"Remove unregistration intent from ETH address "
    return domain_separator + pattern + bytes.fromhex(eth_address[2:]) + int_to_bytes32(pq_nonce)


def sign_with_eth_key(eth_message, eth_private_key):
    # Use Ethereum's personal_sign format
    eth_message_length = len(eth_message)
    eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + eth_message
    eth_message_hash = keccak(eth_signed_message)
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(eth_message_hash, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}


def sign_with_pq_key(pq_message, pq_private_key_file):
    # Use sign_cli.py to sign the PQ message
    from tempfile import NamedTemporaryFile
    import os
    # Write message to temp file
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(pq_message)
        tmp.flush()
        tmp_path = tmp.name
    # Find the project root
    project_root = Path(__file__).resolve().parents[3]  # epervier-registry

    sign_cli = project_root / "ETHFALCON/python-ref/sign_cli.py"
    privkey_path = project_root / "test/test_keys" / pq_private_key_file
    venv_python = project_root / "ETHFALCON/python-ref/myenv/bin/python3"

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
    print("Starting remove intent vector generation...")
    actors = load_actors_config()
    print(f"Loaded {len(actors)} actors from config")
    vectors = []
    
    for actor_name, actor in actors.items():
        print(f"Processing {actor_name.capitalize()}: {actor['eth_address']}")
        eth_address = actor["eth_address"]
        eth_private_key = actor["eth_private_key"]
        pq_private_key_file = actor["pq_private_key_file"]
        pq_fingerprint = actor["pq_fingerprint"]
        eth_nonce = 0
        pq_nonce = 0
        
        # Generate ETH-controlled remove registration intent
        print("Generating ETH remove registration intent...")
        eth_remove_reg_message = build_eth_remove_registration_intent_message(DOMAIN_SEPARATOR, pq_fingerprint, eth_nonce)
        eth_remove_reg_sig = sign_with_eth_key(eth_remove_reg_message, eth_private_key)
        
        # Generate PQ-controlled remove registration intent
        print("Generating PQ remove registration intent...")
        pq_remove_reg_message = build_pq_remove_registration_intent_message(DOMAIN_SEPARATOR, eth_address, pq_nonce)
        pq_remove_reg_sig = sign_with_pq_key(pq_remove_reg_message, pq_private_key_file)
        
        # Generate ETH-controlled remove change intent
        print("Generating ETH remove change intent...")
        eth_remove_change_message = build_eth_remove_change_intent_message(DOMAIN_SEPARATOR, pq_fingerprint, eth_nonce)
        eth_remove_change_sig = sign_with_eth_key(eth_remove_change_message, eth_private_key)
        
        # Generate PQ-controlled remove change intent
        print("Generating PQ remove change intent...")
        pq_remove_change_message = build_pq_remove_change_intent_message(DOMAIN_SEPARATOR, eth_address, pq_nonce)
        pq_remove_change_sig = sign_with_pq_key(pq_remove_change_message, pq_private_key_file)
        
        # Generate ETH-controlled remove unregistration intent
        print("Generating ETH remove unregistration intent...")
        eth_remove_unreg_message = build_eth_remove_unregistration_intent_message(DOMAIN_SEPARATOR, pq_fingerprint, eth_nonce)
        eth_remove_unreg_sig = sign_with_eth_key(eth_remove_unreg_message, eth_private_key)
        
        # Generate PQ-controlled remove unregistration intent
        print("Generating PQ remove unregistration intent...")
        pq_remove_unreg_message = build_pq_remove_unregistration_intent_message(DOMAIN_SEPARATOR, eth_address, pq_nonce)
        pq_remove_unreg_sig = sign_with_pq_key(pq_remove_unreg_message, pq_private_key_file)
        
        # Collect all vectors for this actor
        vector = {
            "actor": actor_name,
            "eth_address": eth_address,
            "pq_fingerprint": pq_fingerprint,
            "eth_remove_registration_intent": {
                "message": eth_remove_reg_message.hex(),
                "signature": eth_remove_reg_sig,
                "eth_nonce": eth_nonce
            },
            "pq_remove_registration_intent": {
                "message": pq_remove_reg_message.hex(),
                "signature": {
                    "salt": pq_remove_reg_sig["salt"].hex(),
                    "cs1": [hex(x) for x in pq_remove_reg_sig["cs1"]],
                    "cs2": [hex(x) for x in pq_remove_reg_sig["cs2"]],
                    "hint": pq_remove_reg_sig["hint"]
                },
                "pq_nonce": pq_nonce
            },
            "eth_remove_change_intent": {
                "message": eth_remove_change_message.hex(),
                "signature": eth_remove_change_sig,
                "eth_nonce": eth_nonce
            },
            "pq_remove_change_intent": {
                "message": pq_remove_change_message.hex(),
                "signature": {
                    "salt": pq_remove_change_sig["salt"].hex(),
                    "cs1": [hex(x) for x in pq_remove_change_sig["cs1"]],
                    "cs2": [hex(x) for x in pq_remove_change_sig["cs2"]],
                    "hint": pq_remove_change_sig["hint"]
                },
                "pq_nonce": pq_nonce
            },
            "eth_remove_unregistration_intent": {
                "message": eth_remove_unreg_message.hex(),
                "signature": eth_remove_unreg_sig,
                "eth_nonce": eth_nonce
            },
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
        json.dump({"remove_intents": vectors}, f, indent=2)
    print("Remove intent vector generation complete!")

if __name__ == "__main__":
    main() 
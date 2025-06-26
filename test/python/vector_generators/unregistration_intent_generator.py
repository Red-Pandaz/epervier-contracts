import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak

print("Script loaded successfully!")

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[3]  # epervier-registry
ACTORS_CONFIG_PATH = PROJECT_ROOT / "test_keys/actors_config.json"
OUTPUT_PATH = PROJECT_ROOT / "test/test_vectors/unregistration_intent_vectors.json"
DOMAIN_SEPARATOR = keccak(b"PQRegistry")

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')


def load_actors_config():
    # Load the actors config JSON
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]


def build_base_eth_unregistration_intent_message(domain_separator, pq_fingerprint, eth_nonce):
    # DOMAIN_SEPARATOR + "Intent to unregister from Epervier fingerprint " + pqFingerprint + ethNonce
    pattern = b"Intent to unregister from Epervier fingerprint "
    return domain_separator + pattern + bytes.fromhex(pq_fingerprint[2:]) + int_to_bytes32(eth_nonce)


def sign_with_eth_key(message_bytes, private_key):
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message_bytes)).encode()
    eth_signed_message = prefix + message_bytes
    eth_signed_message_hash = keccak(eth_signed_message)
    account = Account.from_key(private_key)
    sig = Account._sign_hash(eth_signed_message_hash, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}


def build_pq_unregistration_intent_message(domain_separator, current_eth_address, base_eth_message, eth_signature, pq_nonce):
    # DOMAIN_SEPARATOR + "Intent to unregister from Epervier fingerprint from address " + currentEthAddress + baseETHMessage + v + r + s + pqNonce
    pattern = b"Intent to unregister from Epervier fingerprint from address "
    return (
        domain_separator +
        pattern +
        bytes.fromhex(current_eth_address[2:]) +
        base_eth_message +
        eth_signature["v"].to_bytes(1, "big") +
        eth_signature["r"].to_bytes(32, "big") +
        eth_signature["s"].to_bytes(32, "big") +
        int_to_bytes32(pq_nonce)
    )


def sign_with_pq_key(message, pq_private_key_file):
    from tempfile import NamedTemporaryFile
    import os
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(message)
        tmp.flush()
        tmp_path = tmp.name
    sign_cli = PROJECT_ROOT / "ETHFALCON/python-ref/sign_cli.py"
    privkey_path = PROJECT_ROOT / "test_keys" / pq_private_key_file
    venv_python = PROJECT_ROOT / "ETHFALCON/python-ref/myenv/bin/python3"
    cmd = [
        str(venv_python), str(sign_cli), "sign",
        f"--privkey={privkey_path}",
        f"--data={message.hex()}",
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
    print("Starting unregistration intent vector generation...")
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
        # 1. Build base ETH unregistration intent message
        base_eth_message = build_base_eth_unregistration_intent_message(DOMAIN_SEPARATOR, pq_fingerprint, eth_nonce)
        # 2. ETH sign
        eth_sig = sign_with_eth_key(base_eth_message, eth_private_key)
        # 3. Build PQ unregistration intent message
        pq_message = build_pq_unregistration_intent_message(
            DOMAIN_SEPARATOR, eth_address, base_eth_message,
            {"v": eth_sig["v"], "r": int(eth_sig["r"]), "s": int(eth_sig["s"])}, pq_nonce)
        # 4. PQ sign
        pq_sig = sign_with_pq_key(pq_message, pq_private_key_file)
        if pq_sig is None:
            print(f"Failed to generate PQ signature for {actor_name}!")
            continue
        # 5. Collect all fields
        vector = {
            "actor": actor_name,
            "eth_address": eth_address,
            "pq_fingerprint": pq_fingerprint,
            "base_eth_message": base_eth_message.hex(),
            "eth_signature": {
                "v": eth_sig["v"],
                "r": hex(eth_sig["r"]),
                "s": hex(eth_sig["s"])
            },
            "pq_message": pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            },
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
        vectors.append(vector)
    print(f"Writing {len(vectors)} vectors to {OUTPUT_PATH}")
    with open(OUTPUT_PATH, "w") as f:
        json.dump({"unregistration_intent": vectors}, f, indent=2)
    print("Unregistration intent vector generation complete!")

if __name__ == "__main__":
    main() 
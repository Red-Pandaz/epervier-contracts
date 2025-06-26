#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path
from eth_account import Account
from eth_hash.auto import keccak

# Set project root and paths
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

ACTORS_CONFIG_PATH = project_root / "test" / "test_keys" / "actors_config.json"

# Domain separator
DOMAIN_SEPARATOR = bytes.fromhex("5f5d847b41fe04c02ecf9746150300028bfc195e7981ae8fe39fe8b7a745650f")

def get_actor_config():
    with open(ACTORS_CONFIG_PATH, "r") as f:
        config = json.load(f)
        return config["actors"]

def create_base_pq_confirm_message(domain_separator, old_eth_address, new_eth_address, pq_nonce):
    pattern = b"Confirm changing ETH address from "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(old_eth_address[2:]) +
        b" to " +
        bytes.fromhex(new_eth_address[2:]) +
        pq_nonce.to_bytes(32, "big")
    )
    return message

def sign_eth_message(message_bytes, private_key):
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message_bytes)).encode()
    eth_signed_message = prefix + message_bytes
    eth_signed_message_hash = keccak(eth_signed_message)
    account = Account.from_key(private_key)
    sig = Account._sign_hash(eth_signed_message_hash, private_key=account.key)
    return {"v": sig.v, "r": hex(sig.r), "s": hex(sig.s)}

def sign_pq_message(message, pq_private_key_file):
    try:
        sign_cli = str(project_root / "ETHFALCON" / "python-ref" / "sign_cli.py")
        privkey_path = str(project_root / "test" / "test_keys" / pq_private_key_file)
        cmd = [
            "python3", sign_cli, "sign",
            f"--privkey={privkey_path}",
            f"--data={message.hex()}",
            "--version=epervier"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=project_root / "ETHFALCON" / "python-ref")
        if result.returncode != 0:
            print(f"Error signing message: {result.stderr}")
            return None
        lines = result.stdout.splitlines()
        signature_data = {}
        for line in lines:
            if line.startswith("salt:"):
                signature_data["salt"] = bytes.fromhex(line.split()[1])
            elif line.startswith("hint:"):
                signature_data["hint"] = int(line.split()[1])
            elif line.startswith("cs1:"):
                signature_data["cs1"] = [int(x, 16) for x in line.split()[1:]]
            elif line.startswith("cs2:"):
                signature_data["cs2"] = [int(x, 16) for x in line.split()[1:]]
        if not all(key in signature_data for key in ["salt", "hint", "cs1", "cs2"]):
            print("Failed to parse signature components")
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

def main():
    print("Generating change ETH address confirmation vector for alice -> bob...")
    actors = get_actor_config()
    alice = actors["alice"]
    bob = actors["bob"]
    old_eth_address = alice["eth_address"]
    new_eth_address = bob["eth_address"]
    pq_fingerprint = alice["pq_fingerprint"]
    eth_nonce = 1
    pq_nonce = 3
    print(f"Old ETH Address: {old_eth_address}")
    print(f"New ETH Address: {new_eth_address}")
    print(f"PQ Fingerprint: {pq_fingerprint}")
    print(f"ETH Nonce: {eth_nonce}")
    print(f"PQ Nonce: {pq_nonce}")
    base_pq_message = create_base_pq_confirm_message(DOMAIN_SEPARATOR, old_eth_address, new_eth_address, pq_nonce)
    print(f"Base PQ message length: {len(base_pq_message)}")
    print(f"Base PQ message hex: {base_pq_message.hex()}")
    print(f"Base PQ message ASCII: {base_pq_message}")

    pq_signature = sign_pq_message(base_pq_message, alice["pq_private_key_file"])
    if pq_signature is None:
        print("Failed to generate PQ signature")
        return
    eth_message = (
        DOMAIN_SEPARATOR +
        b"Confirm change ETH Address for Epervier fingerprint " +
        base_pq_message +
        bytes.fromhex(pq_signature["salt"]) +
        b"".join(int(x, 16).to_bytes(32, "big") for x in pq_signature["cs1"]) +
        b"".join(int(x, 16).to_bytes(32, "big") for x in pq_signature["cs2"]) +
        pq_signature["hint"].to_bytes(32, "big") +
        eth_nonce.to_bytes(32, "big")
    )
    print(f"ETH confirmation message length: {len(eth_message)}")
    print(f"ETH confirmation message hex: {eth_message.hex()}")
    print(f"ETH confirmation message ASCII: {eth_message}")

    eth_signature = sign_eth_message(eth_message, bob["eth_private_key"])
    confirmation_vector = {
        "current_actor": "alice",
        "new_actor": "bob",
        "old_eth_address": old_eth_address,
        "new_eth_address": new_eth_address,
        "pq_fingerprint": pq_fingerprint,
        "base_pq_message": base_pq_message.hex(),
        "eth_message": eth_message.hex(),
        "eth_signature": eth_signature,
        "pq_signature": pq_signature,
        "eth_nonce": eth_nonce,
        "pq_nonce": pq_nonce
    }
    output_file = project_root / "test" / "test_vectors" / "change_eth_address_confirmation_vectors.json"
    with open(output_file, "w") as f:
        json.dump({"change_eth_address_confirmation": [confirmation_vector]}, f, indent=2)
    print(f"Confirmation vector saved to {output_file}")
    print("Confirmation vector generated successfully!")

if __name__ == "__main__":
    main()

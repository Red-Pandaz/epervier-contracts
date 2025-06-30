import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak

print("Script loaded successfully!")

# Get the project root directory (four levels up from this script)
project_root = Path(__file__).resolve().parents[4]

ACTORS_CONFIG_PATH = project_root / "test" / "test_keys" / "actors_config.json"
OUTPUT_PATH = project_root / "test/test_vectors/unregister/unregistration_confirmation_vectors.json"
DOMAIN_SEPARATOR = keccak(b"PQRegistry")

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')


def load_actors_config():
    # Load the actors config JSON
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]


def build_base_pq_unregistration_confirm_message(domain_separator, eth_address, pq_nonce):
    # DOMAIN_SEPARATOR + "Confirm unregistration from ETH Address " + ethAddress + pqNonce
    # This matches BasePQUnregistrationConfirmMessage in schema (40 chars pattern)
    # Total length should be: 32 + 40 + 20 + 32 = 124 bytes
    pattern = b"Confirm unregistration from ETH Address "
    return domain_separator + pattern + bytes.fromhex(eth_address[2:]) + int_to_bytes32(pq_nonce)


def create_eth_confirm_message(domain_separator, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    """
    Create ETH message for unregistration confirmation
    Format: DOMAIN_SEPARATOR + "Confirm unregistration from Epervier Fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
    This is signed by the ETH Address
    """
    pattern = b"Confirm unregistration from Epervier Fingerprint "
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        base_pq_message +
        salt +
        pack_uint256_array(cs1) +
        pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') +
        eth_nonce.to_bytes(32, 'big')
    )
    return message


def sign_with_pq_key(base_pq_message, pq_private_key_file):
    # Use sign_cli.py to sign the base PQ message
    from tempfile import NamedTemporaryFile
    import os
    # Write message to temp file
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(base_pq_message)
        tmp.flush()
        tmp_path = tmp.name

    sign_cli = project_root / "ETHFALCON/python-ref/sign_cli.py"
    privkey_path = project_root / "test/test_keys" / pq_private_key_file
    venv_python = project_root / "ETHFALCON/python-ref/myenv/bin/python3"

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


def sign_with_eth_key(eth_message, eth_private_key):
    # Use Ethereum's personal_sign format
    eth_message_length = len(eth_message)
    eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + eth_message
    eth_message_hash = keccak(eth_signed_message)
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(eth_message_hash, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}


def main():
    print("Starting unregistration confirmation vector generation...")
    actors = load_actors_config()
    print(f"Loaded {len(actors)} actors from config")
    vectors = []
    
    for actor_name, actor in actors.items():
        print(f"Processing {actor_name.capitalize()}: {actor['eth_address']}")
        eth_address = actor["eth_address"]
        eth_private_key = actor["eth_private_key"]
        pq_private_key_file = actor["pq_private_key_file"]
        pq_fingerprint = actor["pq_fingerprint"]
        eth_nonce = 3 
        pq_nonce = 3 
        
        # 1. Build base PQ unregistration confirmation message
        print("Building base PQ unregistration confirmation message...")
        base_pq_message = build_base_pq_unregistration_confirm_message(DOMAIN_SEPARATOR, eth_address, pq_nonce)
        print(f"Base PQ message length: {len(base_pq_message)} bytes")
        
        # 2. PQ sign the base message
        print("Signing with PQ key...")
        pq_sig = sign_with_pq_key(base_pq_message, pq_private_key_file)
        if pq_sig is None:
            print(f"Failed to generate PQ signature for {actor_name}!")
            continue
        print(f"PQ signature generated: {len(pq_sig)} components")
        
        # 3. Build ETH unregistration confirmation message
        print("Building ETH unregistration confirmation message...")
        eth_confirmation_message = create_eth_confirm_message(
            DOMAIN_SEPARATOR, pq_fingerprint, base_pq_message, 
            pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce
        )
        print(f"ETH confirmation message length: {len(eth_confirmation_message)} bytes")
        
        # 4. ETH sign the confirmation message
        print("Signing with ETH key...")
        eth_sig = sign_with_eth_key(eth_confirmation_message, eth_private_key)
        print(f"ETH signature generated: v={eth_sig['v']}, r={eth_sig['r']}, s={eth_sig['s']}")
        
        # 5. Collect all fields
        print("Collecting vector data...")
        vector = {
            "actor": actor_name,
            "eth_address": eth_address,
            "pq_fingerprint": pq_fingerprint,
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            },
            "eth_message": eth_confirmation_message.hex(),
            "eth_signature": eth_sig,
            "eth_nonce": eth_nonce,
            "pq_nonce": pq_nonce
        }
        vectors.append(vector)
    
    print(f"Writing {len(vectors)} vectors to {OUTPUT_PATH}")
    # Write vectors to output file
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump({"unregistration_confirmation": vectors}, f, indent=2)
    print("Unregistration confirmation vector generation complete!")

if __name__ == "__main__":
    main() 
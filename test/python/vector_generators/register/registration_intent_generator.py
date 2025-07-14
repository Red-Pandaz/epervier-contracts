import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak
import sys

# Add the parent directory to the path to import eip712_config
sys.path.append(str(Path(__file__).resolve().parents[2]))  # test/python
from eip712_config import DOMAIN_SEPARATOR

print("Script loaded successfully!")

# TODO: import cryptography and web3/eth_account utilities as needed

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[4]  # epervier-registry

# Check for environment variable to use production actors config
import os
ACTORS_CONFIG_FILE = os.environ.get("ACTORS_CONFIG_FILE", "actors_config.json")
ACTORS_CONFIG_PATH = PROJECT_ROOT / "test" / "test_keys" / ACTORS_CONFIG_FILE

print(f"DEBUG: PROJECT_ROOT = {PROJECT_ROOT}")
print(f"DEBUG: ACTORS_CONFIG_PATH = {ACTORS_CONFIG_PATH}")
print(f"DEBUG: File exists: {ACTORS_CONFIG_PATH.exists()}")
print(f"DEBUG: Using actors config: {ACTORS_CONFIG_FILE}")

# Determine output path based on config type
if "production" in ACTORS_CONFIG_FILE:
    OUTPUT_PATH = PROJECT_ROOT / "test/test_vectors/production/register/registration_intent_vectors.json"
else:
    OUTPUT_PATH = PROJECT_ROOT / "test/test_vectors/register/registration_intent_vectors.json"

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')

def encode_packed(*args):
    """Encode packed data (equivalent to abi.encodePacked)"""
    result = b''
    for arg in args:
        if isinstance(arg, bytes):
            result += arg
        elif isinstance(arg, str):
            result += arg.encode('utf-8')
        elif isinstance(arg, int):
            result += arg.to_bytes(32, 'big')
    return result





def load_actors_config():
    # Load the actors config JSON
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]


def build_base_pq_message(domain_separator, eth_address, pq_nonce):
    # DOMAIN_SEPARATOR (32) + "Intent to bind ETH Address " (27) + ethAddress (20) + pqNonce (32) = 111 bytes
    # This matches BasePQRegistrationIntentMessage in schema
    pattern = b"Intent to bind ETH Address "
    # Convert domain_separator from hex string to bytes
    domain_separator_bytes = bytes.fromhex(domain_separator[2:])  # Remove '0x' prefix
    return domain_separator_bytes + pattern + bytes.fromhex(eth_address[2:]) + int_to_bytes32(pq_nonce)


def sign_with_pq_key(base_pq_message, pq_private_key_file):
    # Use sign_cli.py to sign the base PQ message
    # Returns dict with salt, cs1, cs2, hint
    from tempfile import NamedTemporaryFile
    import os
    # Write message to temp file
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(base_pq_message)
        tmp.flush()
        tmp_path = tmp.name
    # Find the project root (assuming this script is at test/python/vector_generators/)
    project_root = Path(__file__).resolve().parents[4]  # epervier-registry

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


def build_eth_intent_message(domain_separator, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    # "Intent to bind Epervier Key" + basePQMessage (with domain separator) + salt + cs1 + cs2 + hint + ethNonce
    # The ETH message contains the complete BasePQRegistrationIntentMessage as per schema
    pattern = b"Intent to bind Epervier Key"
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    
    # Build the ETH message with the complete base PQ message (including domain separator)
    eth_message = (
        pattern + base_pq_message + salt +
        pack_uint256_array(cs1) + pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') + int_to_bytes32(eth_nonce)
    )
    
    return eth_message


def sign_with_eth_key(eth_intent_message, eth_private_key, salt, cs1, cs2, hint, eth_nonce, base_pq_message):
    # Use EIP712 structured signing - domain separator is used in signature verification, not message content
    # Create the struct hash for the message components
    # For EIP712, we need the base PQ message WITH domain separator in the struct hash
    struct_hash = keccak(encode_packed(
        keccak(b"RegistrationIntent(bytes salt,uint256[32] cs1,uint256[32] cs2,uint256 hint,bytes basePQMessage,uint256 ethNonce)"),
        keccak(salt),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs1])),
        keccak(encode_packed(*[x.to_bytes(32, 'big') for x in cs2])),
        hint.to_bytes(32, 'big'),
        keccak(base_pq_message),
        eth_nonce.to_bytes(32, 'big')
    ))
    # Create EIP712 digest with domain separator
    domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix
    digest = keccak(encode_packed(b'\x19\x01', domain_separator_bytes, struct_hash))
    # Sign the digest
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}


def main():
    print("Starting registration intent vector generation...")
    actors = load_actors_config()
    print(f"Loaded {len(actors)} actors from config")
    vectors = []
    for actor_name, actor in actors.items():
        print(f"Processing {actor_name.capitalize()}: {actor['eth_address']}")
        eth_address = actor["eth_address"]
        eth_private_key = actor["eth_private_key"]
        pq_private_key_file = actor["pq_private_key_file"]
        pq_nonce = 0
        eth_nonce = 0
        # 1. Build base PQ message
        print("Building base PQ message...")
        base_pq_message = build_base_pq_message(DOMAIN_SEPARATOR, eth_address, pq_nonce)
        print(f"Base PQ message length: {len(base_pq_message)} bytes")
        # 2. PQ sign
        print("Signing with PQ key...")
        pq_sig = sign_with_pq_key(base_pq_message, pq_private_key_file)
        if pq_sig is None:
            print(f"Failed to generate PQ signature for {actor_name}!")
            continue
        print(f"PQ signature generated: {len(pq_sig)} components")
        # 3. Build ETH intent message
        print("Building ETH intent message...")
        eth_intent_message = build_eth_intent_message(
            DOMAIN_SEPARATOR, base_pq_message, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce
        )
        print(f"ETH intent message length: {len(eth_intent_message)} bytes")
        # 4. ETH sign
        print("Signing with ETH key...")
        eth_sig = sign_with_eth_key(eth_intent_message, eth_private_key, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce, base_pq_message)
        print(f"ETH signature generated: v={eth_sig['v']}, r={eth_sig['r']}, s={eth_sig['s']}")
        # 5. Collect all fields
        print("Collecting vector data...")
        vector = {
            "actor": actor_name,
            "eth_address": eth_address,
            "pq_fingerprint": actor["pq_fingerprint"],
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            },
            "eth_message": eth_intent_message.hex(),
            "eth_signature": {
                "v": eth_sig["v"],
                "r": f"0x{eth_sig['r']:064x}",
                "s": f"0x{eth_sig['s']:064x}"
            },
            "eth_nonce": eth_nonce
        }
        vectors.append(vector)
    print(f"Writing {len(vectors)} vectors to {OUTPUT_PATH}")
    with open(OUTPUT_PATH, "w") as f:
        json.dump({"registration_intent": vectors}, f, indent=2)
    print("Vector generation complete!")

if __name__ == "__main__":
    main() 
import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak
import hashlib

print("Script loaded successfully!")

# Get the project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[4]  # epervier-registry
ACTORS_CONFIG_PATH = PROJECT_ROOT / "test" / "test_keys" / "actors_config.json"
OUTPUT_PATH = PROJECT_ROOT / "test/test_vectors/unregister/unregistration_intent_vectors.json"
DOMAIN_SEPARATOR = keccak(b"PQRegistry")

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')


def load_actors_config():
    # Load the actors config JSON
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]


def create_base_eth_message(domain_separator, pq_fingerprint, eth_nonce):
    """
    Create base ETH message for unregistration intent
    Format: DOMAIN_SEPARATOR + "Intent to unregister from Epervier Fingerprint " + pqFingerprint + ethNonce
    This is signed by the ETH Address
    """
    pattern = b"Intent to unregister from Epervier Fingerprint "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(pq_fingerprint[2:]) +  # Remove "0x" prefix
        eth_nonce.to_bytes(32, 'big')
    )
    return message


def create_base_pq_message(domain_separator, current_eth_address, base_eth_message, v, r, s, pq_nonce):
    """
    Create base PQ message for unregistration intent
    Format: DOMAIN_SEPARATOR + "Intent to unregister from Epervier Fingerprint from address " + currentEthAddress + baseETHMessage + v + r + s + pqNonce
    This is signed by the PQ key
    """
    pattern = b"Intent to unregister from Epervier Fingerprint from address "
    message = (
        domain_separator +
        pattern +
        bytes.fromhex(current_eth_address[2:]) +  # Remove "0x" prefix
        base_eth_message +
        v.to_bytes(1, 'big') +
        r.to_bytes(32, 'big') +
        s.to_bytes(32, 'big') +
        pq_nonce.to_bytes(32, 'big')
    )
    return message


def create_eth_message_for_signing(domain_separator, eth_nonce, pq_message):
    """
    Create ETH message for signing in unregistration intent
    Format: DOMAIN_SEPARATOR + "Intent to unregister from Epervier Fingerprint from address " + ethNonce + pqMessage
    This is what the ETH signature should sign
    """
    pattern = b"Intent to unregister from Epervier Fingerprint from address "
    message = (
        domain_separator +
        pattern +
        eth_nonce.to_bytes(32, 'big') +
        pq_message
    )
    return message


def sign_with_eth_key(message_bytes, private_key):
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message_bytes)).encode()
    eth_signed_message = prefix + message_bytes
    eth_signed_message_hash = keccak(eth_signed_message)
    account = Account.from_key(private_key)
    sig = Account._sign_hash(eth_signed_message_hash, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}


def sign_with_pq_key(message, pq_private_key_file):
    from tempfile import NamedTemporaryFile
    import os
    with NamedTemporaryFile(delete=False) as tmp:
        tmp.write(message)
        tmp.flush()
        tmp_path = tmp.name
    sign_cli = PROJECT_ROOT / "ETHFALCON/python-ref/sign_cli.py"
    privkey_path = PROJECT_ROOT / "test/test_keys" / pq_private_key_file
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
        eth_nonce = 2  # Use nonce 2 to match current contract state
        pq_nonce = 2   # Use current PQ nonce (2 after registration)
        
        # 1. Build base ETH unregistration intent message (for inclusion in PQ message)
        base_eth_message = create_base_eth_message(DOMAIN_SEPARATOR, pq_fingerprint, eth_nonce)
        
        # 2. Create PQ message without ETH signature components (this is what ETH signs)
        # Format: DOMAIN_SEPARATOR + pattern + ethAddress + baseETHMessage + pqNonce
        pattern = b"Intent to unregister from Epervier Fingerprint from address "
        pq_message_without_eth_sig = (
            DOMAIN_SEPARATOR +
            pattern +
            bytes.fromhex(eth_address[2:]) +  # Remove "0x" prefix
            base_eth_message +
            pq_nonce.to_bytes(32, 'big')
        )
        
        # 3. Create the ETH message that includes the PQ message without ETH signature
        # Format: DOMAIN_SEPARATOR + "Intent to unregister from Epervier Fingerprint from address " + ethNonce + pqMessageWithoutSignature
        eth_message = (
            DOMAIN_SEPARATOR +
            b"Intent to unregister from Epervier Fingerprint from address " +
            eth_nonce.to_bytes(32, 'big') +
            pq_message_without_eth_sig
        )
        
        # 4. Sign the baseETHMessage using eth_account (Ethereum style)
        # The ETH signature should sign the baseETHMessage directly (BaseETHUnregistrationIntentMessage)
        # If eth_private_key is a hex string, convert to bytes
        if isinstance(eth_private_key, str):
            if eth_private_key.startswith("0x"):
                eth_private_key_bytes = bytes.fromhex(eth_private_key[2:])
            else:
                eth_private_key_bytes = bytes.fromhex(eth_private_key)
        else:
            eth_private_key_bytes = eth_private_key

        account = Account.from_key(eth_private_key_bytes)
        eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(len(base_eth_message)).encode() + base_eth_message
        eth_signed_message_hash = keccak(eth_signed_message)
        sig = Account._sign_hash(eth_signed_message_hash, private_key=account.key)
        v, r, s = sig.v, sig.r, sig.s
        
        # 5. Build complete PQ message with ETH signature components
        pq_message = create_base_pq_message(
            DOMAIN_SEPARATOR, eth_address, base_eth_message,
            v, r, s, pq_nonce)
        
        # 6. PQ sign the final PQ message
        pq_sig = sign_with_pq_key(pq_message, pq_private_key_file)
        if pq_sig is None:
            print(f"Failed to generate PQ signature for {actor_name}!")
            continue
            
        # 7. Collect all fields
        vector = {
            "actor": actor_name,
            "eth_address": eth_address,
            "pq_fingerprint": pq_fingerprint,
            "base_eth_message": base_eth_message.hex(),
            "eth_signature": {
                "v": v,
                "r": hex(r),
                "s": hex(s)
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
    # Write vectors to output file
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump({"unregistration_intent": vectors}, f, indent=2)
    print("Unregistration intent vector generation complete!")

if __name__ == "__main__":
    main() 
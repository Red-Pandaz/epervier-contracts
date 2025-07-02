import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak
import sys
sys.path.append(str(Path(__file__).resolve().parents[2]))  # Add python directory to path
from eip712_helpers import get_unregistration_confirmation_struct_hash, sign_eip712_message, encode_packed
from eip712_config import DOMAIN_SEPARATOR

print("Script loaded successfully!")

# Get the project root directory (four levels up from this script)
project_root = Path(__file__).resolve().parents[4]

ACTORS_CONFIG_PATH = project_root / "test" / "test_keys" / "actors_config.json"
OUTPUT_PATH = project_root / "test/test_vectors/unregister/unregistration_confirmation_vectors.json"
domain_separator_bytes = bytes.fromhex(DOMAIN_SEPARATOR[2:])  # Remove '0x' prefix

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
    Format: "Confirm unregistration from Epervier Fingerprint " + pqFingerprint + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
    This is signed by the ETH Address (no domain separator in content for EIP712)
    """
    pattern = b"Confirm unregistration from Epervier Fingerprint "
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    
    message = (
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


def sign_with_eth_key(eth_message, eth_private_key, pq_fingerprint, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    """Sign a message with ETH private key using EIP712"""
    # Use EIP712 structured signing
    # First create the struct hash
    struct_hash = get_unregistration_confirmation_struct_hash(pq_fingerprint, eth_nonce)
    
    # Create EIP712 digest with domain separator (same as working registration generators)
    from eth_utils import keccak
    from eip712_helpers import encode_packed
    
    # domain_separator_bytes is already bytes from the import
    digest = keccak(encode_packed(b'\x19\x01', domain_separator_bytes, struct_hash))
    
    print(f"DEBUG: Python domain_separator_bytes: {domain_separator_bytes.hex()}")
    print(f"DEBUG: Python struct_hash: {struct_hash.hex()}")
    print(f"DEBUG: Python digest: {digest.hex()}")
    
    # Sign the digest using the same pattern as working registration generators
    from eth_account import Account
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(digest, private_key=account.key)
    
    # Verify the signature immediately
    recovered_address = Account._recover_hash(digest, vrs=(sig.v, sig.r, sig.s))
    print(f"DEBUG: Python recovered_address: {recovered_address}")
    print(f"DEBUG: Python expected_address: {account.address}")
    print(f"DEBUG: Python addresses_match: {recovered_address.lower() == account.address.lower()}")
    
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
        
        # Debug: Show the private key being used
        from eth_account import Account
        debug_account = Account.from_key(eth_private_key)
        print(f"DEBUG: Python using private_key: {eth_private_key}")
        print(f"DEBUG: Python account address: {debug_account.address}")
        print(f"DEBUG: Python expected address: {eth_address}")
        print(f"DEBUG: Python addresses_match: {debug_account.address.lower() == eth_address.lower()}") 
        
        # 1. Build base PQ unregistration confirmation message
        print("Building base PQ unregistration confirmation message...")
        base_pq_message = build_base_pq_unregistration_confirm_message(domain_separator_bytes, eth_address, pq_nonce)
        print(f"Base PQ message length: {len(base_pq_message)} bytes")
        
        # 2. PQ sign the base message
        print("Signing with PQ key...")
        pq_sig = sign_with_pq_key(base_pq_message, pq_private_key_file)
        if pq_sig is None:
            print(f"Failed to generate PQ signature for {actor_name}!")
            continue
        print(f"PQ signature generated: {len(pq_sig)} components")
        print(f"DEBUG: Python PQ signature components:")
        print(f"  salt: {pq_sig['salt'].hex()}")
        print(f"  hint: {pq_sig['hint']}")
        print(f"  cs1[0]: {pq_sig['cs1'][0]}")
        print(f"  cs1[1]: {pq_sig['cs1'][1]}")
        print(f"  cs2[0]: {pq_sig['cs2'][0]}")
        print(f"  cs2[1]: {pq_sig['cs2'][1]}")
        print(f"  base_pq_message: {base_pq_message.hex()}")
        
        # 3. Build ETH unregistration confirmation message
        print("Building ETH unregistration confirmation message...")
        eth_confirmation_message = create_eth_confirm_message(
            domain_separator_bytes, pq_fingerprint, base_pq_message, 
            pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce
        )
        print(f"ETH confirmation message length: {len(eth_confirmation_message)} bytes")
        print(f"ETH confirmation message (hex): {eth_confirmation_message.hex()}")
        # Print offsets and lengths for each field
        pattern_len = 49
        pq_fp_len = 20
        base_pq_len = len(base_pq_message)
        salt_len = len(pq_sig["salt"])
        cs1_len = 32*32
        cs2_len = 32*32
        hint_len = 32
        eth_nonce_len = 32
        print(f"Field offsets and lengths:")
        print(f"  pattern: offset 0, length {pattern_len}")
        print(f"  pqFingerprint: offset {pattern_len}, length {pq_fp_len}")
        print(f"  basePQMessage: offset {pattern_len + pq_fp_len}, length {base_pq_len}")
        print(f"  salt: offset {pattern_len + pq_fp_len + base_pq_len}, length {salt_len}")
        print(f"  cs1: offset {pattern_len + pq_fp_len + base_pq_len + salt_len}, length {cs1_len}")
        print(f"  cs2: offset {pattern_len + pq_fp_len + base_pq_len + salt_len + cs1_len}, length {cs2_len}")
        print(f"  hint: offset {pattern_len + pq_fp_len + base_pq_len + salt_len + cs1_len + cs2_len}, length {hint_len}")
        print(f"  ethNonce: offset {pattern_len + pq_fp_len + base_pq_len + salt_len + cs1_len + cs2_len + hint_len}, length {eth_nonce_len}")
        # Print hex slices for each field
        offset = 0
        print(f"  pattern: {eth_confirmation_message[offset:offset+pattern_len].hex()}")
        offset += pattern_len
        print(f"  pqFingerprint: {eth_confirmation_message[offset:offset+pq_fp_len].hex()}")
        offset += pq_fp_len
        print(f"  basePQMessage: {eth_confirmation_message[offset:offset+base_pq_len].hex()}")
        offset += base_pq_len
        print(f"  salt: {eth_confirmation_message[offset:offset+salt_len].hex()}")
        offset += salt_len
        print(f"  cs1: {eth_confirmation_message[offset:offset+cs1_len].hex()}")
        offset += cs1_len
        print(f"  cs2: {eth_confirmation_message[offset:offset+cs2_len].hex()}")
        offset += cs2_len
        print(f"  hint: {eth_confirmation_message[offset:offset+hint_len].hex()}")
        offset += hint_len
        print(f"  ethNonce: {eth_confirmation_message[offset:offset+eth_nonce_len].hex()}")
        
        # 4. ETH sign the confirmation message
        print("Signing with ETH key...")
        eth_sig = sign_with_eth_key(eth_confirmation_message, eth_private_key, pq_fingerprint, base_pq_message, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce)
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
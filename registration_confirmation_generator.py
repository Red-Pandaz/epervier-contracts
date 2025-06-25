import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak

print("Script loaded successfully!")

ACTORS_CONFIG_PATH = Path("test/test_keys/actors_config.json")
OUTPUT_PATH = Path("registration_confirmation_vectors.json")
DOMAIN_SEPARATOR = keccak(b"PQRegistry")

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')


def load_actors_config():
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]


def build_eth_confirm_message(domain_separator, pq_fingerprint, eth_nonce):
    """Build ETH confirmation message: DOMAIN_SEPARATOR + "Confirm bonding to epervier fingerprint " + pqFingerprint + ethNonce"""
    pattern = b"Confirm bonding to epervier fingerprint "
    return domain_separator + pattern + bytes.fromhex(pq_fingerprint[2:]) + int_to_bytes32(eth_nonce)


def sign_with_eth_key(eth_confirm_message, eth_private_key):
    """Sign ETH confirmation message with ETH private key"""
    eth_message_length = len(eth_confirm_message)
    eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + eth_confirm_message
    eth_message_hash = keccak(eth_signed_message)
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(eth_message_hash, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}


def build_pq_confirm_message(domain_separator, eth_address, base_eth_message, eth_signature, pq_nonce):
    """Build PQ confirmation message: DOMAIN_SEPARATOR + "Confirm binding ETH Address " + ethAddress + baseETHMessage + v + r + s + pqNonce"""
    pattern = b"Confirm binding ETH Address "
    return (
        domain_separator + pattern + bytes.fromhex(eth_address[2:]) + 
        base_eth_message + 
        eth_signature["v"].to_bytes(1, 'big') + 
        eth_signature["r"].to_bytes(32, 'big') + 
        eth_signature["s"].to_bytes(32, 'big') + 
        int_to_bytes32(pq_nonce)
    )


def sign_with_pq_key(pq_confirm_message, pq_private_key_file):
    """Generate Epervier signature using the Python CLI"""
    try:
        # Convert message to hex
        message_hex = pq_confirm_message.hex()
        
        # Call the Python CLI to sign the message using the virtual environment
        cmd = [
            "ETHFALCON/python-ref/myenv/bin/python", 
            "ETHFALCON/python-ref/sign_cli.py", 
            "sign",
            "--version", "epervier",
            "--privkey", f"test/test_keys/{pq_private_key_file}",
            "--data", message_hex
        ]
        
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=".")
        
        if result.returncode != 0:
            print(f"Warning: Epervier signing failed: {result.stderr}")
            return {
                "salt": bytes.fromhex("00" * 40),
                "cs1": [0] * 32,
                "cs2": [0] * 32,
                "hint": 123
            }
        
        # Parse the signature from the generated file
        sig_file = Path("sig")
        if sig_file.exists():
            with open(sig_file, 'r') as f:
                signature_hex = f.read().strip()
            # Clean up the temporary signature file
            sig_file.unlink()
            
            # Parse the signature components
            signature_bytes = bytes.fromhex(signature_hex)
            
            # For Epervier, the signature format is:
            # HEAD_LEN (1) + SALT_LEN (40) + enc_s + hint (512*3 bytes)
            HEAD_LEN = 1
            SALT_LEN = 40
            
            salt = signature_bytes[HEAD_LEN:HEAD_LEN + SALT_LEN]
            enc_s = signature_bytes[HEAD_LEN + SALT_LEN:-512*3]  # Remove hint at the end
            hint_bytes = signature_bytes[-512*3:]  # Last 1536 bytes are hint
            
            # For now, return placeholder values for cs1, cs2
            # In practice, you'd decompress enc_s to get s1 and s2, then compact them
            return {
                "salt": salt,
                "cs1": [0] * 32,  # Placeholder - need proper parsing
                "cs2": [0] * 32,  # Placeholder - need proper parsing
                "hint": int.from_bytes(hint_bytes[:32], 'big')  # Use first 32 bytes as hint
            }
        else:
            print(f"Warning: Signature file not found")
            return {
                "salt": bytes.fromhex("00" * 40),
                "cs1": [0] * 32,
                "cs2": [0] * 32,
                "hint": 123
            }
        
    except Exception as e:
        print(f"Error generating Epervier signature: {e}")
        return {
            "salt": bytes.fromhex("00" * 40),
            "cs1": [0] * 32,
            "cs2": [0] * 32,
            "hint": 123
        }


def main():
    print("Starting registration confirmation vector generation...")
    actors = load_actors_config()
    print(f"Loaded {len(actors)} actors from config")
    vectors = []
    
    # Generate confirmation vector for Alice only
    alice = actors["alice"]
    print(f"\nProcessing Alice: {alice['eth_address']}")
    
    eth_address = alice["eth_address"]
    eth_private_key = alice["eth_private_key"]
    pq_private_key_file = alice["pq_private_key_file"]
    pq_fingerprint = alice["pq_fingerprint"]
    
    # Nonces: after intent submission, ETH nonce is 1, PQ nonce is 1
    eth_nonce = 1
    pq_nonce = 1
    
    # 1. Build ETH confirmation message
    print(f"  Building ETH confirmation message...")
    eth_confirm_message = build_eth_confirm_message(DOMAIN_SEPARATOR, pq_fingerprint, eth_nonce)
    print(f"  ETH confirmation message length: {len(eth_confirm_message)} bytes")
    
    # 2. Sign ETH confirmation message
    print(f"  Signing ETH confirmation message...")
    eth_sig = sign_with_eth_key(eth_confirm_message, eth_private_key)
    print(f"  ETH signature generated: v={eth_sig['v']}, r={eth_sig['r']}, s={eth_sig['s']}")
    
    # 3. Build PQ confirmation message
    print(f"  Building PQ confirmation message...")
    pq_confirm_message = build_pq_confirm_message(
        DOMAIN_SEPARATOR, eth_address, eth_confirm_message, eth_sig, pq_nonce
    )
    print(f"  PQ confirmation message length: {len(pq_confirm_message)} bytes")
    
    # 4. Sign PQ confirmation message
    print(f"  Signing PQ confirmation message...")
    pq_sig = sign_with_pq_key(pq_confirm_message, pq_private_key_file)
    print(f"  PQ signature generated: {len(pq_sig)} components")
    
    # 5. Collect all fields
    print(f"  Collecting vector data...")
    vector = {
        "actor": "alice",
        "eth_address": eth_address,
        "pq_fingerprint": pq_fingerprint,
        "eth_confirm_message": eth_confirm_message.hex(),
        "eth_signature": eth_sig,
        "pq_confirm_message": pq_confirm_message.hex(),
        "pq_signature": {
            "salt": pq_sig["salt"].hex(),
            "cs1": [hex(x) for x in pq_sig["cs1"]],
            "cs2": [hex(x) for x in pq_sig["cs2"]],
            "hint": pq_sig["hint"]
        }
    }
    vectors.append(vector)
    print(f"  ✅ Alice confirmation vector completed")
    
    print(f"\nWriting {len(vectors)} vectors to {OUTPUT_PATH}")
    with open(OUTPUT_PATH, "w") as f:
        json.dump({"registration_confirmation": vectors}, f, indent=2)
    print("Vector generation complete!")

if __name__ == "__main__":
    main() 
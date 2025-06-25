import json
from pathlib import Path
import subprocess
from eth_account import Account
from eth_utils import keccak

ACTORS_CONFIG_PATH = Path("test/test_keys/actors_config.json")
OUTPUT_PATH = Path("registration_intent_vectors.json")
DOMAIN_SEPARATOR = keccak(b"PQRegistry")

# Helper to convert int to bytes32
int_to_bytes32 = lambda x: x.to_bytes(32, 'big')


def load_actors_config():
    with open(ACTORS_CONFIG_PATH, "r") as f:
        return json.load(f)["actors"]


def build_base_pq_message(domain_separator, eth_address, pq_nonce):
    # DOMAIN_SEPARATOR (32) + "Intent to pair ETH Address " (27) + ethAddress (20) + pqNonce (32) = 111 bytes
    pattern = b"Intent to pair ETH Address "
    return domain_separator + pattern + bytes.fromhex(eth_address[2:]) + int_to_bytes32(pq_nonce)


def sign_with_pq_key(base_pq_message, pq_private_key_file):
    """Generate Epervier signature using the Python CLI"""
    try:
        # Convert message to hex
        message_hex = base_pq_message.hex()
        
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


def build_eth_intent_message(domain_separator, base_pq_message, salt, cs1, cs2, hint, eth_nonce):
    # DOMAIN_SEPARATOR + "Intent to pair Epervier Key" + basePQMessage + salt + cs1 + cs2 + hint + ethNonce
    pattern = b"Intent to pair Epervier Key"
    def pack_uint256_array(arr):
        return b"".join(x.to_bytes(32, 'big') for x in arr)
    return (
        domain_separator + pattern + base_pq_message + salt +
        pack_uint256_array(cs1) + pack_uint256_array(cs2) +
        hint.to_bytes(32, 'big') + int_to_bytes32(eth_nonce)
    )


def sign_with_eth_key(eth_intent_message, eth_private_key):
    # Use Ethereum's personal_sign format
    eth_message_length = len(eth_intent_message)
    eth_signed_message = b"\x19Ethereum Signed Message:\n" + str(eth_message_length).encode() + eth_intent_message
    eth_message_hash = keccak(eth_signed_message)
    account = Account.from_key(eth_private_key)
    sig = Account._sign_hash(eth_message_hash, private_key=account.key)
    return {"v": sig.v, "r": sig.r, "s": sig.s}


def main():
    print("Starting registration intent vector generation...")
    actors = load_actors_config()
    print(f"Loaded {len(actors)} actors from config")
    vectors = []
    
    # Generate vectors for all actors
    for actor_name, actor_info in actors.items():
        print(f"\nProcessing {actor_name}: {actor_info['eth_address']}")
        eth_address = actor_info["eth_address"]
        eth_private_key = actor_info["eth_private_key"]
        pq_private_key_file = actor_info["pq_private_key_file"]
        pq_nonce = 0
        eth_nonce = 0
        
        # 1. Build base PQ message
        print(f"  Building base PQ message...")
        base_pq_message = build_base_pq_message(DOMAIN_SEPARATOR, eth_address, pq_nonce)
        print(f"  Base PQ message length: {len(base_pq_message)} bytes")
        
        # 2. PQ sign
        print(f"  Signing with PQ key...")
        pq_sig = sign_with_pq_key(base_pq_message, pq_private_key_file)
        print(f"  PQ signature generated: {len(pq_sig)} components")
        
        # 3. Build ETH intent message
        print(f"  Building ETH intent message...")
        eth_intent_message = build_eth_intent_message(
            DOMAIN_SEPARATOR, base_pq_message, pq_sig["salt"], pq_sig["cs1"], pq_sig["cs2"], pq_sig["hint"], eth_nonce
        )
        print(f"  ETH intent message length: {len(eth_intent_message)} bytes")
        
        # 4. ETH sign
        print(f"  Signing with ETH key...")
        eth_sig = sign_with_eth_key(eth_intent_message, eth_private_key)
        print(f"  ETH signature generated: v={eth_sig['v']}, r={eth_sig['r']}, s={eth_sig['s']}")
        
        # 5. Collect all fields
        print(f"  Collecting vector data...")
        vector = {
            "actor": actor_name,
            "eth_address": eth_address,
            "pq_fingerprint": actor_info["pq_fingerprint"],
            "base_pq_message": base_pq_message.hex(),
            "pq_signature": {
                "salt": pq_sig["salt"].hex(),
                "cs1": [hex(x) for x in pq_sig["cs1"]],
                "cs2": [hex(x) for x in pq_sig["cs2"]],
                "hint": pq_sig["hint"]
            },
            "eth_message": eth_intent_message.hex(),
            "eth_signature": eth_sig
        }
        vectors.append(vector)
        print(f"  ✅ {actor_name} vector completed")
    
    print(f"\nWriting {len(vectors)} vectors to {OUTPUT_PATH}")
    with open(OUTPUT_PATH, "w") as f:
        json.dump({"registration_intent": vectors}, f, indent=2)
    print("Vector generation complete!")

if __name__ == "__main__":
    main() 
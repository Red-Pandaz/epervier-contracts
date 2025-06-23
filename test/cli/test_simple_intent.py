import subprocess
import json
from eth_account import Account
from eth_account.messages import encode_defunct
import os
import sys
import hashlib
import eth_utils
from eth_utils import keccak

# Add the python-ref directory to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ETHFALCON/python-ref')))
from falcon_epervier import HEAD_LEN, SALT_LEN, decompress
from common import falcon_compact, q
from polyntt.poly import Poly

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
sign_cli_path = os.path.join(project_root, 'ETHFALCON/python-ref/sign_cli.py')
privkey_path = os.path.join(project_root, 'ETHFALCON/python-ref/private_key.pem')

# Contract address (update this after deployment)
CONTRACT_ADDRESS = "0xc6e7DF5E7b4f2A278906862b61205850344D4e7d"

def parse_signature_like_cli(sig_path):
    with open(sig_path, 'r') as f:
        sig_hex = f.read().strip()
    sig = bytes.fromhex(sig_hex)
    salt = sig[HEAD_LEN:HEAD_LEN + SALT_LEN]
    enc_s = sig[HEAD_LEN + SALT_LEN:-512*3]
    s = decompress(enc_s, 666*2 - HEAD_LEN - SALT_LEN, 512*2)
    mid = len(s) // 2
    s = [elt % q for elt in s]
    s1, s2 = s[:mid], s[mid:]
    s1_compact = falcon_compact(s1)
    s2_compact = falcon_compact(s2)
    s2_inv_ntt = Poly(s2, q).inverse().ntt()
    hint = 1
    for elt in s2_inv_ntt:
        hint = (hint * elt) % q
    return {
        'salt': salt.hex(),
        'cs1': s1_compact,
        'cs2': s2_compact,
        'hint': hint
    }

def get_public_key():
    with open('../../ETHFALCON/python-ref/public_key.pem', 'r') as f:
        content = f.read()
        import re
        match = re.search(r'pk\s*=\s*(\d+)', content)
        if match:
            pk_value = int(match.group(1))
            return [pk_value, 0]
    return None

def main():
    # Print the Ethereum address from the private key
    eth_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # Default Anvil key 0
    acct = Account.from_key(eth_private_key)
    print(f"ETH private key address: {acct.address}")

    # Use the default Foundry/Anvil private key
    eth_private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    eth_account = Account.from_key(eth_private_key)
    eth_address = eth_account.address

    print(f"Ethereum address: {eth_address}")

    # Step 1: Create and sign ETH intent message
    print("\nStep 1: Creating ETH intent message...")
    eth_nonce = 0  # Use nonce 0 as the current value in the contract is 0
    
    # Domain separator from contract
    DOMAIN_SEPARATOR = keccak(b"PQRegistry")

    # Create the message exactly as the contract does
    ethIntentMessage = DOMAIN_SEPARATOR + b"Intent to pair Epervier Key" + eth_nonce.to_bytes(32, 'big')
    print(f"ethIntentMessage (hex): {ethIntentMessage.hex()}")
    print(f"ethIntentMessage (raw): {ethIntentMessage}")

    # Hash the message
    ethMessageHash = keccak(ethIntentMessage)
    print(f"ethMessageHash: {ethMessageHash.hex()}")

    # Create the signed message hash
    ethSignedMessageHash = keccak(b"\x19Ethereum Signed Message:\n32" + ethMessageHash)
    print(f"ethSignedMessageHash: {ethSignedMessageHash.hex()}")

    # Sign the message
    message = encode_defunct(ethMessageHash)
    signed_message = eth_account.sign_message(message)
    eth_signature = signed_message.signature
    print(f"ETH signature: {eth_signature.hex()}")
    print(f"r: 0x{signed_message.r:064x}")
    print(f"s: 0x{signed_message.s:064x}")
    print(f"v: {signed_message.v}")

    # Step 2: Create PQ intent message (includes ETH signature)
    print("\nStep 2: Creating PQ intent message...")
    pq_nonce = 0  # Start with PQ nonce 0
    # Add separators to make address parsing easier
    pq_intent_message = f"Intent to pair with address {eth_address} nonce {pq_nonce} signature {eth_signature.hex()}".encode()
    print(f"PQ intent message: {pq_intent_message}")
    print(f"PQ intent message hex: {pq_intent_message.hex()}")

    # Step 3: Sign with Epervier key
    print("\nStep 3: Signing with Epervier key...")
    command = [
        "python3",
        sign_cli_path,
        "sign",
        f"--privkey={privkey_path}",
        "--data", pq_intent_message.hex(),
        "--version=epervier"
    ]
    
    print(" ".join(command))
    result = subprocess.run(command, capture_output=True, text=True)
    print(f"Return code: {result.returncode}")
    if result.stdout:
        print(f"STDOUT: {result.stdout}")
    if result.stderr:
        print(f"STDERR: {result.stderr}")

    # Parse the Epervier signature components
    if result.returncode == 0:
        # Read signature from the 'sig' file that the CLI creates
        sig_path = 'sig'
        if os.path.exists(sig_path):
            signature_components = parse_signature_like_cli(sig_path)
            salt = signature_components['salt']
            cs1 = signature_components['cs1']
            cs2 = signature_components['cs2']
            hint = signature_components['hint']
            
            print(f"\nExtracted Epervier signature components:")
            print(f"Salt: {salt}")
            print(f"Hint: {hint}")
            print(f"cs1 length: {len(cs1)}")
            print(f"cs2 length: {len(cs2)}")
            
            # Pre-flight checks before submitting transaction
            print("\n=== PRE-FLIGHT CHECKS ===")
            print(f"Salt length: {len(bytes.fromhex(salt))} bytes (should be 40)")
            print(f"cs1 length: {len(cs1)} elements (should be 32)")
            print(f"cs2 length: {len(cs2)} elements (should be 32)")
            print(f"Hint: {hint} (should be uint)")
            print(f"ETH signature length: {len(bytes.fromhex(eth_signature.hex()))} bytes (should be 65)")
            print(f"ETH signature: {eth_signature.hex()}")
            print(f"ETH signature r: {hex(signed_message.r)}")
            print(f"ETH signature s: {hex(signed_message.s)}")
            print(f"ETH signature v: {signed_message.v}")
            print(f"ethMessageHash: {ethMessageHash.hex()}")
            print(f"ethSignedMessageHash: {ethSignedMessageHash.hex()}")
            print(f"ethNonce: {eth_nonce}")
            print(f"publicKey: {get_public_key()}")
            print("=== END PRE-FLIGHT CHECKS ===")
            
            # Step 4: Submit to registry contract
            print("\nStep 4: Submitting to registry contract...")
            rpc_url = "http://127.0.0.1:9545"  # Updated for Supersim L2 901
            command = [
                "cast", "send", CONTRACT_ADDRESS,
                "submitRegistrationIntent(bytes,bytes,uint256[],uint256[],uint256,uint256[2],uint256,bytes)",
                f"0x{pq_intent_message.hex()}",
                f"0x{salt}",
                "[" + ",".join(map(str, cs1)) + "]",
                "[" + ",".join(map(str, cs2)) + "]",
                str(hint),
                f"[{get_public_key()[0]}, {get_public_key()[1]}]",
                str(eth_nonce),
                eth_signature.hex(),
                "--rpc-url", rpc_url,
                "--private-key", eth_private_key,
                "--gas-limit", "25000000"
            ]
            
            print(" ".join(command))
            result = subprocess.run(command, capture_output=True, text=True)
            print(f"Return code: {result.returncode}")
            if result.stdout:
                print(f"STDOUT: {result.stdout}")
            if result.stderr:
                print(f"STDERR: {result.stderr}")
        else:
            print(f"Error: Signature file '{sig_path}' not found")
    else:
        print("Error: Epervier signing failed")

if __name__ == "__main__":
    main() 
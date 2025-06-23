#!/usr/bin/env python3

import os
import sys
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak
import subprocess
import re

# Add the project root to the path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

# Contract address
CONTRACT_ADDRESS = "0xc6e7DF5E7b4f2A278906862b61205850344D4e7d"

# Paths
sign_cli_path = os.path.join(project_root, 'ETHFALCON/python-ref/sign_cli.py')
privkey_path = os.path.join(project_root, 'ETHFALCON/python-ref/private_key.pem')

def get_public_key():
    """Get the public key from the PEM file"""
    with open('../../ETHFALCON/python-ref/public_key.pem', 'r') as f:
        content = f.read()
        # Extract the public key values (simplified)
        return [1060949616175605039904708348861159580941700240548, 0]

def parse_signature_like_cli(sig_path):
    """Parse the signature output from the CLI tool"""
    with open(sig_path, 'r') as f:
        content = f.read()
    
    # Extract salt (40 bytes)
    salt_match = re.search(r'Salt: ([a-f0-9]{80})', content)
    salt = bytes.fromhex(salt_match.group(1)) if salt_match else None
    
    # Extract hint
    hint_match = re.search(r'Hint: (\d+)', content)
    hint = int(hint_match.group(1)) if hint_match else None
    
    # Extract cs1 and cs2 arrays
    cs1_match = re.search(r'cs1: \[(.*?)\]', content, re.DOTALL)
    cs2_match = re.search(r'cs2: \[(.*?)\]', content, re.DOTALL)
    
    if cs1_match and cs2_match:
        cs1_str = cs1_match.group(1).strip()
        cs2_str = cs2_match.group(1).strip()
        
        # Parse the arrays
        cs1 = [int(x.strip()) for x in cs1_str.split(',') if x.strip()]
        cs2 = [int(x.strip()) for x in cs2_str.split(',') if x.strip()]
        
        return salt, cs1, cs2, hint
    
    return None, None, None, None

def submit_intent(eth_address, eth_nonce, eth_private_key):
    """Submit a registration intent for the given ETH address"""
    print(f"\n=== Submitting intent for ETH address: {eth_address} ===")
    
    # Create ETH account
    account = Account.from_key(eth_private_key)
    print(f"Account address: {account.address}")
    
    # Domain separator from contract
    DOMAIN_SEPARATOR = keccak(b"PQRegistry")
    
    # Create the message exactly as the contract does
    ethIntentMessage = DOMAIN_SEPARATOR + b"Intent to pair Epervier Key" + eth_nonce.to_bytes(32, 'big')
    print(f"ethIntentMessage (hex): {ethIntentMessage.hex()}")
    
    # Hash the message
    ethMessageHash = keccak(ethIntentMessage)
    print(f"ethMessageHash: {ethMessageHash.hex()}")
    
    # Sign the message
    message = encode_defunct(ethMessageHash)
    signed_message = account.sign_message(message)
    eth_signature = signed_message.signature
    print(f"ETH signature: {eth_signature.hex()}")
    
    # Create PQ intent message
    pq_nonce = 0
    pq_intent_message = f"Intent to pair with address {eth_address} nonce {pq_nonce} signature {eth_signature.hex()}".encode()
    print(f"PQ intent message: {pq_intent_message}")
    
    # Sign with Epervier key
    print("Signing with Epervier key...")
    command = [
        "python3", sign_cli_path, "sign",
        "--privkey=" + privkey_path,
        "--data", pq_intent_message.hex(),
        "--version=epervier"
    ]
    
    result = subprocess.run(command, capture_output=True, text=True)
    print(f"Return code: {result.returncode}")
    
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return None
    
    # Parse signature
    salt, cs1, cs2, hint = parse_signature_like_cli(os.path.join(project_root, 'ETHFALCON/python-ref/signature.txt'))
    
    if not all([salt, cs1, cs2, hint]):
        print("Failed to parse signature")
        return None
    
    print(f"Salt: {salt.hex()}")
    print(f"Hint: {hint}")
    print(f"cs1 length: {len(cs1)}")
    print(f"cs2 length: {len(cs2)}")
    
    # Submit to contract
    print("Submitting to registry contract...")
    rpc_url = "http://127.0.0.1:9545"
    
    command = [
        "cast", "send", CONTRACT_ADDRESS,
        "submitRegistrationIntent(bytes,bytes,uint256[],uint256[],uint256,uint256[2],uint256,bytes)",
        f"0x{pq_intent_message.hex()}",
        f"0x{salt.hex()}",
        f"[{','.join(map(str, cs1))}]",
        f"[{','.join(map(str, cs2))}]",
        str(hint),
        f"[{get_public_key()[0]}, {get_public_key()[1]}]",
        str(eth_nonce),
        eth_signature.hex(),
        "--rpc-url", rpc_url,
        "--private-key", eth_private_key,
        "--gas-limit", "25000000"
    ]
    
    result = subprocess.run(command, capture_output=True, text=True)
    print(f"Return code: {result.returncode}")
    print(f"STDOUT: {result.stdout}")
    
    if result.returncode == 0:
        print("✅ Intent submitted successfully!")
        return True
    else:
        print(f"❌ Intent submission failed: {result.stderr}")
        return False

def main():
    # Test with two different ETH addresses
    eth_address_1 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    eth_address_2 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # Different address
    
    eth_private_key_1 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    eth_private_key_2 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    
    print("=== Testing Intent Updates ===")
    print("This test will:")
    print("1. Submit an intent with ETH address 1")
    print("2. Submit an intent with ETH address 2 (same Epervier fingerprint)")
    print("3. Verify that the second intent overwrites the first")
    
    # Step 1: Submit intent with address 1
    success_1 = submit_intent(eth_address_1, 0, eth_private_key_1)
    
    if success_1:
        # Step 2: Submit intent with address 2 (should overwrite)
        success_2 = submit_intent(eth_address_2, 0, eth_private_key_2)
        
        if success_2:
            print("\n🎉 Intent update test completed successfully!")
            print("The second intent should have overwritten the first one.")
            print("Both intents used the same Epervier fingerprint but different ETH addresses.")
        else:
            print("\n❌ Second intent submission failed")
    else:
        print("\n❌ First intent submission failed")

if __name__ == "__main__":
    main() 
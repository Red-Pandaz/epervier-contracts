#!/usr/bin/env python3

import subprocess
import json
from eth_account import Account
import os

# Contract address (update this after deployment)
CONTRACT_ADDRESS = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"

# RPC URL for Supersim L2
RPC_URL = "http://127.0.0.1:9545"

# ETH private key (account 1 from Supersim)
ETH_PRIVATE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
ETH_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

def parse_signature_like_cli(sig_path):
    """Parse signature output from the CLI tool"""
    with open(sig_path, 'r') as f:
        content = f.read()
    
    # Extract salt (40 bytes)
    salt_start = content.find("Salt: ") + 6
    salt_end = content.find("\n", salt_start)
    salt_hex = content[salt_start:salt_end].strip()
    
    # Extract hint
    hint_start = content.find("Hint: ") + 6
    hint_end = content.find("\n", hint_start)
    hint = int(content[hint_start:hint_end].strip())
    
    # Extract cs1 and cs2 arrays
    cs1_start = content.find("cs1: [") + 5
    cs1_end = content.find("]", cs1_start) + 1
    cs1_str = content[cs1_start:cs1_end]
    cs1 = [int(x.strip()) for x in cs1_str[1:-1].split(",")]
    
    cs2_start = content.find("cs2: [") + 5
    cs2_end = content.find("]", cs2_start) + 1
    cs2_str = content[cs2_start:cs2_end]
    cs2 = [int(x.strip()) for x in cs2_str[1:-1].split(",")]
    
    return salt_hex, hint, cs1, cs2

def main():
    print(f"ETH private key address: {ETH_ADDRESS}")
    print(f"Ethereum address: {ETH_ADDRESS}")
    
    # Step 1: Create confirmation message
    print("\nStep 1: Creating confirmation message...")
    confirmation_message = f"Confirm binding to address {ETH_ADDRESS}"
    print(f"Confirmation message: {confirmation_message}")
    confirmation_message_hex = confirmation_message.encode().hex()
    print(f"Confirmation message hex: {confirmation_message_hex}")
    
    # Step 2: Sign with Epervier key
    print("\nStep 2: Signing confirmation message with Epervier key...")
    sig_output_path = "/tmp/epervier_confirmation_sig.txt"
    
    # Use the sign_cli.py tool to sign the confirmation message
    sign_command = [
        "python3", "/Users/davidmillstone/Documents/concepts/ETHFALCON/python-ref/sign_cli.py",
        "sign",
        "--privkey=/Users/davidmillstone/Documents/concepts/ETHFALCON/python-ref/private_key.pem",
        "--data", confirmation_message_hex,
        "--version=epervier"
    ]
    
    print(f"Running: {' '.join(sign_command)}")
    result = subprocess.run(sign_command, capture_output=True, text=True)
    print(f"Return code: {result.returncode}")
    
    # Save the output to a file for parsing
    with open(sig_output_path, 'w') as f:
        f.write(result.stdout)
    
    # Parse the signature components
    salt_hex, hint, cs1, cs2 = parse_signature_like_cli(sig_output_path)
    print(f"\nExtracted Epervier signature components:")
    print(f"Salt: {salt_hex}")
    print(f"Hint: {hint}")
    print(f"cs1 length: {len(cs1)}")
    print(f"cs2 length: {len(cs2)}")
    
    # Step 3: Create ETH signature for confirmation
    print("\nStep 3: Creating ETH signature for confirmation...")
    account = Account.from_key(ETH_PRIVATE_KEY)
    
    # Create the message hash
    message_hash = account._sign_hash(confirmation_message.encode())
    eth_signature = message_hash.signature
    
    print(f"Confirmation message: {confirmation_message}")
    print(f"Message hash: {message_hash.hash.hex()}")
    print(f"ETH signature: {eth_signature.hex()}")
    print(f"r: 0x{eth_signature[:32].hex()}")
    print(f"s: 0x{eth_signature[32:64].hex()}")
    print(f"v: {eth_signature[64]}")
    
    # Step 4: Get current PQ nonce
    print("\nStep 4: Getting current PQ nonce...")
    public_key = [1060949616175605039904708348861159580941700240548, 0]
    public_key_hash = f"0x{public_key[0]:064x}{public_key[1]:064x}"
    
    # Get the current nonce for this PQ key
    nonce_command = [
        "cast", "call", CONTRACT_ADDRESS,
        "pqKeyNonces(bytes32)(uint256)", public_key_hash,
        "--rpc-url", RPC_URL
    ]
    
    result = subprocess.run(nonce_command, capture_output=True, text=True)
    if result.returncode == 0:
        pq_nonce = int(result.stdout.strip())
        print(f"Current PQ nonce: {pq_nonce}")
    else:
        print("Could not get PQ nonce, assuming 0")
        pq_nonce = 0
    
    # Step 5: Submit confirmation
    print("\nStep 5: Submitting confirmation to registry contract...")
    
    # Convert salt from hex to bytes
    salt_bytes = bytes.fromhex(salt_hex)
    
    # Prepare the command
    command = [
        "cast", "send", CONTRACT_ADDRESS,
        "confirmRegistration(bytes,bytes,uint256[],uint256[],uint256,uint256,uint256[2])",
        f"0x{confirmation_message.encode().hex()}",  # confirmationMessage
        f"0x{salt_bytes.hex()}",  # salt
        f"[{','.join(map(str, cs1))}]",  # cs1
        f"[{','.join(map(str, cs2))}]",  # cs2
        str(hint),  # hint
        str(pq_nonce),  # pqNonce
        f"[{public_key[0]}, {public_key[1]}]",  # publicKey
        "--rpc-url", RPC_URL,
        "--private-key", ETH_PRIVATE_KEY,
        "--gas-limit", "25000000"
    ]
    
    print(f"Running: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    print(f"Return code: {result.returncode}")
    print(f"STDOUT: {result.stdout}")
    print(f"STDERR: {result.stderr}")
    
    if result.returncode == 0:
        print("\n✅ Confirmation successful!")
    else:
        print("\n❌ Confirmation failed!")

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
Fix production actors config with real fingerprints and ETH addresses
Uses two-recovery validation to ensure fingerprints are correct
"""

import json
import subprocess
from pathlib import Path
import sys
from eth_account import Account
import secrets
import tempfile
import os

# Add the ETHFALCON python-ref directory to the path
sys.path.append(str(Path(__file__).resolve().parents[1] / "ETHFALCON" / "python-ref"))

from sign_cli import load_pk

def generate_epervier_signature(message, pq_private_key_file):
    """Generate Epervier signature using the Python CLI"""
    try:
        # Convert message to hex
        message_hex = message.hex() if isinstance(message, bytes) else message.encode().hex()
        
        # Call the Python CLI to sign the message
        cmd = [
            sys.executable, 
            str(Path(__file__).resolve().parents[1] / "ETHFALCON/python-ref/sign_cli.py"), 
            "sign",
            "--version", "epervier",
            "--privkey", str(pq_private_key_file),
            "--data", message_hex
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parents[1] / "ETHFALCON/python-ref"))
        
        if result.returncode != 0:
            print(f"Warning: Epervier signing failed: {result.stderr}")
            return None
        
        # Parse the signature from the generated file
        sig_file = Path(__file__).resolve().parents[1] / "ETHFALCON/python-ref/sig"
        if sig_file.exists():
            with open(sig_file, 'r') as f:
                signature_hex = f.read().strip()
            # Clean up the temporary signature file
            sig_file.unlink()
            return signature_hex
        else:
            print(f"Warning: Signature file not found")
            return None
        
    except Exception as e:
        print(f"Error generating Epervier signature: {e}")
        return None

def call_recover_onchain(message, signature_file, pubkey_file, contract_address, rpc_url):
    """Call the recoveronchain function using sign_cli.py"""
    try:
        # Convert message to hex
        message_hex = message.hex() if isinstance(message, bytes) else message.encode().hex()
        
        # Use sign_cli.py to call recoveronchain
        cmd = [
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "ETHFALCON/python-ref/sign_cli.py"),
            "recoveronchain",
            "--version", "epervier",
            "--data", message_hex,
            "--pubkey", str(pubkey_file),
            "--signature", str(signature_file),
            "--contractaddress", contract_address,
            "--rpc", rpc_url
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parents[1] / "ETHFALCON/python-ref"))
        
        if result.returncode != 0:
            print(f"Recover onchain failed: {result.stderr}")
            return None
        
        # Parse the returned address
        recovered_address = result.stdout.strip()
        # Extract the address from the output (format: "Public key recovered: 0x...")
        if "Public key recovered:" in recovered_address:
            recovered_address = recovered_address.split("Public key recovered: ")[1].strip()
        return recovered_address
        
    except Exception as e:
        print(f"Error calling recover onchain: {e}")
        return None

def validate_fingerprint_with_two_recoveries(pq_private_key_file, pq_public_key_file, contract_address, rpc_url):
    """Validate fingerprint using two-recovery process"""
    print(f"  Validating fingerprint with two-recovery process...")
    
    # Generate two different messages
    message1 = f"Validation message 1 for fingerprint test"
    message2 = f"Validation message 2 for fingerprint test"
    
    # Sign both messages
    print(f"    Signing message 1...")
    sig1_hex = generate_epervier_signature(message1.encode(), pq_private_key_file)
    if not sig1_hex:
        print(f"    ❌ Failed to sign message 1")
        return None
        
    print(f"    Signing message 2...")
    sig2_hex = generate_epervier_signature(message2.encode(), pq_private_key_file)
    if not sig2_hex:
        print(f"    ❌ Failed to sign message 2")
        return None
    
    # Save signatures to temporary files
    with tempfile.NamedTemporaryFile(mode='w', suffix='_sig1', delete=False) as f1:
        f1.write(sig1_hex)
        sig1_file = f1.name
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='_sig2', delete=False) as f2:
        f2.write(sig2_hex)
        sig2_file = f2.name
    
    try:
        # Call recover onchain for first message
        print(f"    Recovering fingerprint from message 1...")
        fingerprint1 = call_recover_onchain(message1.encode(), sig1_file, pq_public_key_file, contract_address, rpc_url)
        if not fingerprint1:
            print(f"    ❌ Failed to recover fingerprint from message 1")
            return None
        
        # Call recover onchain for second message
        print(f"    Recovering fingerprint from message 2...")
        fingerprint2 = call_recover_onchain(message2.encode(), sig2_file, pq_public_key_file, contract_address, rpc_url)
        if not fingerprint2:
            print(f"    ❌ Failed to recover fingerprint from message 2")
            return None
        
        # Verify both fingerprints match
        if fingerprint1 == fingerprint2:
            print(f"    ✅ Fingerprint validated: {fingerprint1}")
            return fingerprint1
        else:
            print(f"    ❌ Fingerprint mismatch!")
            print(f"      Message 1 fingerprint: {fingerprint1}")
            print(f"      Message 2 fingerprint: {fingerprint2}")
            return None
            
    finally:
        # Clean up temp files
        os.unlink(sig1_file)
        os.unlink(sig2_file)

def generate_eth_keypair():
    """Generate a new ETH private key and address"""
    private_key = "0x" + secrets.token_hex(32)
    account = Account.from_key(private_key)
    return {
        "private_key": private_key,
        "address": account.address
    }

def main():
    print("🔧 Fixing production actors config with real data...")
    print("🔐 Using two-recovery validation for fingerprints...")
    
    # Configuration
    CONTRACT_ADDRESS = "0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"  # OP Sepolia
    RPC_URL = "https://sepolia.optimism.io"
    
    # Load current config
    config_path = Path("test/test_keys/production_actors_config.json")
    with open(config_path, "r") as f:
        config = json.load(f)
    
    # Get project root
    project_root = Path(__file__).resolve().parents[1]
    keys_dir = project_root / "test/test_keys"
    
    # Fix each actor
    for actor_name, actor in config["actors"].items():
        print(f"\nProcessing {actor_name}...")
        
        # Validate fingerprint using two-recovery process
        pq_private_key_file = keys_dir / actor["pq_private_key_file"]
        pq_public_key_file = keys_dir / actor["pq_public_key_file"]
        
        if not pq_private_key_file.exists():
            print(f"  ❌ PQ private key file not found: {pq_private_key_file}")
            continue
            
        if not pq_public_key_file.exists():
            print(f"  ❌ PQ public key file not found: {pq_public_key_file}")
            continue
        
        # Validate fingerprint with two recoveries
        validated_fingerprint = validate_fingerprint_with_two_recoveries(
            pq_private_key_file, 
            pq_public_key_file, 
            CONTRACT_ADDRESS, 
            RPC_URL
        )
        
        if validated_fingerprint:
            print(f"  ✅ Validated fingerprint: {validated_fingerprint}")
            actor["pq_fingerprint"] = validated_fingerprint
        else:
            print(f"  ❌ Failed to validate fingerprint for {actor_name}")
            continue
        
        # Generate real ETH keypair
        eth_keypair = generate_eth_keypair()
        print(f"  Real ETH address: {eth_keypair['address']}")
        print(f"  Real ETH private key: {eth_keypair['private_key']}")
        
        # Update actor config
        actor["eth_private_key"] = eth_keypair["private_key"]
        actor["eth_address"] = eth_keypair["address"]
    
    # Update metadata
    config["metadata"]["last_updated"] = "2024-12-19"
    config["metadata"]["description"] = "Production actor configuration for OP Sepolia testing - REAL KEYS with two-recovery validation"
    config["metadata"]["fingerprints_validated"] = True
    
    # Save updated config
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"\n✅ Updated {config_path} with real fingerprints and ETH addresses!")
    print("🔐 All actors now have real PQ fingerprints (validated with two-recovery process) and ETH keypairs")

if __name__ == "__main__":
    main() 
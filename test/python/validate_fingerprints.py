#!/usr/bin/env python3
"""
Validate fingerprints for all actors by calling recovery function on OP Sepolia
"""

import json
import subprocess
import sys
from pathlib import Path
from eth_account import Account
from eth_hash.auto import keccak

# Configuration
SCRIPT_DIR = Path(__file__).parent
OP_SEPOLIA_RPC = "https://sepolia.optimism.io"
CONTRACT_ADDRESS = "0x5ab1d6db02f48bad63cbef5d51c534A76aEB824B"
ACTORS_CONFIG_FILE = SCRIPT_DIR.parent / "test_keys" / "actors_config.json"

def load_actors_config():
    """Load the actors configuration file"""
    if not ACTORS_CONFIG_FILE.exists():
        print(f"Error: {ACTORS_CONFIG_FILE} not found")
        return None
    
    with open(ACTORS_CONFIG_FILE, 'r') as f:
        return json.load(f)

def save_actors_config(config):
    """Save the updated actors configuration file"""
    with open(ACTORS_CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def generate_epervier_signature(message, pq_private_key_file):
    """Generate Epervier signature using the Python CLI"""
    try:
        # Convert message to hex
        message_hex = message.hex() if isinstance(message, bytes) else message.encode().hex()
        
        # Call the Python CLI to sign the message
        cmd = [
            sys.executable, 
            str(SCRIPT_DIR.parent.parent / "ETHFALCON/python-ref/sign_cli.py"), 
            "sign",
            "--version", "epervier",
            "--privkey", str(SCRIPT_DIR.parent / "test_keys" / pq_private_key_file),
            "--data", message_hex
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(SCRIPT_DIR))
        
        if result.returncode != 0:
            print(f"Warning: Epervier signing failed: {result.stderr}")
            return None
        
        # Parse the signature from the generated file
        sig_file = SCRIPT_DIR / "sig"
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
            str(SCRIPT_DIR.parent.parent / "ETHFALCON/python-ref/sign_cli.py"),
            "recoveronchain",
            "--version", "epervier",
            "--data", message_hex,
            "--pubkey", str(SCRIPT_DIR.parent / "test_keys" / pubkey_file),
            "--signature", str(signature_file),
            "--contractaddress", contract_address,
            "--rpc", rpc_url
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(SCRIPT_DIR))
        
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

def validate_fingerprints():
    """Validate fingerprints for all actors"""
    print("Validating fingerprints for all actors...")
    print(f"Contract: {CONTRACT_ADDRESS}")
    print(f"RPC: {OP_SEPOLIA_RPC}")
    
    # Load actors configuration
    config = load_actors_config()
    if not config:
        return
    
    actors = config["actors"]
    validated_count = 0
    
    for actor_name, actor_data in actors.items():
        print(f"\nValidating fingerprint for {actor_name} (index {actor_data['index']})...")
        print(f"  ETH Address: {actor_data['eth_address']}")
        print(f"  PQ Private Key: {actor_data['pq_private_key_file']}")
        
        # Generate two different messages
        message1 = f"Message 1 for {actor_name}"
        message2 = f"Message 2 for {actor_name}"
        
        # Sign both messages
        print(f"  Signing message 1: '{message1}'")
        sig1_hex = generate_epervier_signature(message1.encode(), actor_data['pq_private_key_file'])
        if not sig1_hex:
            print(f"  Failed to sign message 1 for {actor_name}")
            continue
            
        print(f"  Signing message 2: '{message2}'")
        sig2_hex = generate_epervier_signature(message2.encode(), actor_data['pq_private_key_file'])
        if not sig2_hex:
            print(f"  Failed to sign message 2 for {actor_name}")
            continue
        
        # Save signatures to temporary files
        sig1_file = SCRIPT_DIR / f"sig_{actor_name}_1"
        sig2_file = SCRIPT_DIR / f"sig_{actor_name}_2"
        
        with open(sig1_file, 'w') as f:
            f.write(sig1_hex)
        with open(sig2_file, 'w') as f:
            f.write(sig2_hex)
        
        # Call recover onchain for first message
        print(f"  Calling recover onchain for message 1...")
        fingerprint1 = call_recover_onchain(message1.encode(), sig1_file, actor_data['pq_public_key_file'], CONTRACT_ADDRESS, OP_SEPOLIA_RPC)
        if not fingerprint1:
            print(f"  Failed to recover fingerprint for message 1")
            # Clean up temp files
            sig1_file.unlink(missing_ok=True)
            sig2_file.unlink(missing_ok=True)
            continue
        
        # Call recover onchain for second message
        print(f"  Calling recover onchain for message 2...")
        fingerprint2 = call_recover_onchain(message2.encode(), sig2_file, actor_data['pq_public_key_file'], CONTRACT_ADDRESS, OP_SEPOLIA_RPC)
        if not fingerprint2:
            print(f"  Failed to recover fingerprint for message 2")
            # Clean up temp files
            sig1_file.unlink(missing_ok=True)
            sig2_file.unlink(missing_ok=True)
            continue
        
        # Clean up temp files
        sig1_file.unlink(missing_ok=True)
        sig2_file.unlink(missing_ok=True)
        
        # Verify both fingerprints match
        if fingerprint1 == fingerprint2:
            print(f"  ✅ Fingerprint validated: {fingerprint1}")
            # Update the config with the validated fingerprint
            actors[actor_name]["pq_fingerprint"] = fingerprint1
            validated_count += 1
        else:
            print(f"  ❌ Fingerprint mismatch!")
            print(f"    Message 1 fingerprint: {fingerprint1}")
            print(f"    Message 2 fingerprint: {fingerprint2}")
    
    # Update metadata
    config["metadata"]["fingerprints_validated"] = True
    config["metadata"]["validated_count"] = validated_count
    
    # Save updated configuration
    save_actors_config(config)
    
    print(f"\n✅ Validated {validated_count} fingerprints")
    print(f"Updated {ACTORS_CONFIG_FILE}")
    
    # Also save detailed validation results
    validation_file = SCRIPT_DIR.parent / "test_keys" / "fingerprint_validation_results.json"
    validation_results = {
        "contract_address": CONTRACT_ADDRESS,
        "rpc_url": OP_SEPOLIA_RPC,
        "validated_count": validated_count,
        "total_actors": len(actors),
        "timestamp": "2024-06-25"
    }
    
    with open(validation_file, 'w') as f:
        json.dump(validation_results, f, indent=2)
    
    print(f"Validation results saved to {validation_file}")

if __name__ == "__main__":
    validate_fingerprints() 
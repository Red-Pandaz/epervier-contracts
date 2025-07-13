#!/usr/bin/env python3
"""
Generate production ETH keypairs for OP Sepolia testing
"""

import json
from pathlib import Path
from eth_account import Account
import secrets

def generate_eth_keypair():
    """Generate a new ETH private key and address"""
    private_key = "0x" + secrets.token_hex(32)
    account = Account.from_key(private_key)
    return {
        "private_key": private_key,
        "address": account.address
    }

def main():
    # Actors to generate
    actors = ["kyle", "luke", "marie", "nancy", "oscar"]
    
    # Load existing config
    config_path = Path("test/test_keys/production_actors_config.json")
    with open(config_path, "r") as f:
        config = json.load(f)
    
    # Generate new keypairs
    for i, actor in enumerate(actors):
        keypair = generate_eth_keypair()
        
        # Update config with real keypair
        config["actors"][actor] = {
            "index": i + 4,  # Start after existing actors
            "eth_private_key": keypair["private_key"],
            "eth_address": keypair["address"],
            "pq_private_key_file": f"prod_private_key_{i+5}.pem",
            "pq_public_key_file": f"prod_public_key_{i+5}.pem",
            "pq_fingerprint": f"0x000000000000000000000000000000000000000{i+5:02d}"
        }
        
        print(f"Generated {actor.capitalize()}:")
        print(f"  Address: {keypair['address']}")
        print(f"  Private Key: {keypair['private_key']}")
        print()
    
    # Update metadata
    config["metadata"]["total_actors"] = len(config["actors"])
    config["metadata"]["last_updated"] = "2024-12-19"
    
    # Save updated config
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"✅ Generated {len(actors)} new keypairs")
    print(f"✅ Updated {config_path}")
    print("⚠️  Remember: These are real private keys - keep them secure!")

if __name__ == "__main__":
    main() 
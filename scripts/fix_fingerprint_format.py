#!/usr/bin/env python3
"""
Fix fingerprint format to be exactly 20 bytes (40 hex characters)
"""

import json
from pathlib import Path

def fix_fingerprint_format(fingerprint):
    """Fix fingerprint to be exactly 20 bytes"""
    if not fingerprint.startswith('0x'):
        return fingerprint
    
    # Remove the 0x prefix
    hex_part = fingerprint[2:]
    
    # Remove leading zeros to get the actual 20-byte value
    # The fingerprint should be exactly 40 hex characters (20 bytes)
    if len(hex_part) > 40:
        # If it's longer than 40 chars, take the last 40
        hex_part = hex_part[-40:]
    elif len(hex_part) < 40:
        # If it's shorter than 40 chars, pad with leading zeros
        hex_part = hex_part.zfill(40)
    
    return "0x" + hex_part

def main():
    print("🔧 Fixing fingerprint format to be exactly 20 bytes...")
    
    # Load current config
    config_path = Path("test/test_keys/production_actors_config.json")
    with open(config_path, "r") as f:
        config = json.load(f)
    
    # Fix each actor's fingerprint
    for actor_name, actor in config["actors"].items():
        print(f"Processing {actor_name}...")
        old_fingerprint = actor["pq_fingerprint"]
        new_fingerprint = fix_fingerprint_format(old_fingerprint)
        
        if old_fingerprint != new_fingerprint:
            print(f"  Fixed fingerprint:")
            print(f"    Old: {old_fingerprint}")
            print(f"    New: {new_fingerprint}")
            actor["pq_fingerprint"] = new_fingerprint
        else:
            print(f"  ✅ Fingerprint already correct: {new_fingerprint}")
    
    # Update metadata
    config["metadata"]["fingerprint_format_fixed"] = True
    config["metadata"]["last_updated"] = "2024-12-19"
    
    # Save updated config
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    print(f"\n✅ Updated {config_path} with properly formatted fingerprints!")
    print("🔐 All fingerprints are now exactly 20 bytes (40 hex characters)")

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
Generate PQ keypairs for production actors
"""

import json
import subprocess
from pathlib import Path
import os
import sys

# Add the ETHFALCON python-ref directory to the path
sys.path.append(str(Path(__file__).resolve().parents[1] / "ETHFALCON" / "python-ref"))

from sign_cli import generate_keys, save_pk, save_sk

def generate_pq_keypair(key_number):
    """Generate a PQ keypair using the ETHFALCON tools"""
    project_root = Path(__file__).resolve().parents[1]  # epervier-contracts
    output_dir = project_root / "test/test_keys"
    
    # Generate private key
    private_key_path = output_dir / f"prod_private_key_{key_number}.pem"
    public_key_path = output_dir / f"prod_public_key_{key_number}.pem"
    
    print(f"Generating PQ keypair {key_number}...")
    
    try:
        # Generate keys using the function from sign_cli.py
        sk, pk = generate_keys(512, 'epervier')  # Use 512-bit keys for epervier
        
        # Save the keys
        save_sk(sk, str(private_key_path), 'epervier')
        save_pk(pk, str(public_key_path), 'epervier')
        
        print(f"✅ Generated PQ keypair {key_number}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to generate PQ keypair {key_number}: {e}")
        return False

def main():
    print("🔑 Generating PQ keypairs for production actors...")
    
    # Generate 9 keypairs (for alice through oscar)
    success_count = 0
    for i in range(1, 10):  # 1 through 9
        if generate_pq_keypair(i):
            success_count += 1
    
    print(f"\n🎉 Generated {success_count}/9 PQ keypairs")
    
    if success_count == 9:
        print("✅ All PQ keypairs generated successfully!")
        print("📁 Keys saved to test/test_keys/prod_private_key_*.pem")
        print("📁 Keys saved to test/test_keys/prod_public_key_*.pem")
    else:
        print("❌ Some keypairs failed to generate")

if __name__ == "__main__":
    main() 
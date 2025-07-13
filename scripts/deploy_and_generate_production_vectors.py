#!/usr/bin/env python3
"""
Deploy production contracts and generate vectors with correct domain separators
"""

import json
import subprocess
import re
from pathlib import Path
import os

def deploy_production_contracts():
    """Deploy production contracts using Foundry"""
    print("🚀 Deploying production contracts...")
    
    # Set a dummy private key for deployment (will be overridden by env var)
    os.environ["PRIVATE_KEY"] = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    
    # Run deployment script
    cmd = [
        "forge", "script", "script/DeployProduction.s.sol",
        "--rpc-url", "http://localhost:8545",
        "--broadcast"
    ]
    
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("❌ Deployment failed!")
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        return None, None
    
    print("✅ Production contracts deployed successfully!")
    
    # Extract contract addresses and domain separators from output
    registry_address = None
    nft_address = None
    registry_domain_separator = None
    nft_domain_separator = None
    
    for line in result.stdout.split('\n'):
        if "PQRegistry deployed at:" in line:
            registry_address = line.split(":")[-1].strip()
        elif "PQERC721 deployed at:" in line:
            nft_address = line.split(":")[-1].strip()
        elif "Domain separator:" in line:
            registry_domain_separator = line.split(":")[-1].strip()
        elif "PQERC721 domain separator:" in line:
            nft_domain_separator = line.split(":")[-1].strip()
    
    return {
        "registry_address": registry_address,
        "nft_address": nft_address,
        "registry_domain_separator": registry_domain_separator,
        "nft_domain_separator": nft_domain_separator
    }

def update_domain_separators_in_generators(contract_info):
    """Update domain separators in the vector generators"""
    print("📝 Updating domain separators in vector generators...")
    
    # Update registration intent generator
    intent_generator_path = Path("test/python/vector_generators/production/register/registration_intent_generator.py")
    if intent_generator_path.exists():
        with open(intent_generator_path, "r") as f:
            content = f.read()
        
        # Replace the placeholder domain separator
        content = content.replace(
            'return "0x0000000000000000000000000000000000000000000000000000000000000000"',
            f'return "{contract_info["registry_domain_separator"]}"'
        )
        
        with open(intent_generator_path, "w") as f:
            f.write(content)
        print("✅ Updated registration intent generator")
    
    # Update registration confirmation generator
    confirmation_generator_path = Path("test/python/vector_generators/production/register/registration_confirmation_generator.py")
    if confirmation_generator_path.exists():
        with open(confirmation_generator_path, "r") as f:
            content = f.read()
        
        # Replace the placeholder domain separator
        content = content.replace(
            'return "0x0000000000000000000000000000000000000000000000000000000000000000"',
            f'return "{contract_info["registry_domain_separator"]}"'
        )
        
        with open(confirmation_generator_path, "w") as f:
            f.write(content)
        print("✅ Updated registration confirmation generator")
    
    # Update PQ transfer generator
    transfer_generator_path = Path("test/python/vector_generators/production/transfer/pq_transfer_generator.py")
    if transfer_generator_path.exists():
        with open(transfer_generator_path, "r") as f:
            content = f.read()
        
        # Replace the placeholder domain separator
        content = content.replace(
            'return "0x0000000000000000000000000000000000000000000000000000000000000000"',
            f'return "{contract_info["nft_domain_separator"]}"'
        )
        
        with open(transfer_generator_path, "w") as f:
            f.write(content)
        print("✅ Updated PQ transfer generator")

def generate_production_vectors():
    """Generate all production vectors"""
    print("🔧 Generating production vectors...")
    
    # Generate registration intent vectors
    print("Generating registration intent vectors...")
    cmd = ["python3", "test/python/vector_generators/production/register/registration_intent_generator.py"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("✅ Registration intent vectors generated")
    else:
        print("❌ Registration intent generation failed:", result.stderr)
    
    # Generate registration confirmation vectors
    print("Generating registration confirmation vectors...")
    cmd = ["python3", "test/python/vector_generators/production/register/registration_confirmation_generator.py"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("✅ Registration confirmation vectors generated")
    else:
        print("❌ Registration confirmation generation failed:", result.stderr)
    
    # Generate PQ transfer vectors
    print("Generating PQ transfer vectors...")
    cmd = ["python3", "test/python/vector_generators/production/transfer/pq_transfer_generator.py"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("✅ PQ transfer vectors generated")
    else:
        print("❌ PQ transfer generation failed:", result.stderr)

def save_contract_info(contract_info):
    """Save contract information for later use"""
    info_path = Path("test/test_vectors/dev/contract_info.json")
    with open(info_path, "w") as f:
        json.dump(contract_info, f, indent=2)
    print(f"✅ Contract info saved to {info_path}")

def main():
    print("=== PRODUCTION VECTOR GENERATION ===")
    print()
    
    # Step 1: Deploy contracts
    contract_info = deploy_production_contracts()
    if not contract_info:
        print("❌ Failed to deploy contracts. Exiting.")
        return
    
    print(f"Registry address: {contract_info['registry_address']}")
    print(f"NFT address: {contract_info['nft_address']}")
    print(f"Registry domain separator: {contract_info['registry_domain_separator']}")
    print(f"NFT domain separator: {contract_info['nft_domain_separator']}")
    print()
    
    # Step 2: Update domain separators in generators
    update_domain_separators_in_generators(contract_info)
    print()
    
    # Step 3: Generate vectors
    generate_production_vectors()
    print()
    
    # Step 4: Save contract info
    save_contract_info(contract_info)
    print()
    
    print("🎉 PRODUCTION VECTOR GENERATION COMPLETE!")
    print("📁 Vectors saved to test/test_vectors/dev/")
    print("🔐 Contract info saved to test/test_vectors/dev/contract_info.json")

if __name__ == "__main__":
    main() 